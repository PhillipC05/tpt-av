package patrol

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/tpt-av/tpt-av/internal/config"
	"github.com/tpt-av/tpt-av/internal/events"
	"github.com/tpt-av/tpt-av/internal/heuristics"
)

const debounceWindow = 500 * time.Millisecond

// FileDetector is satisfied by both yara.Scanner (CGo) and its noop stub.
type FileDetector interface {
	ScanFile(path string) ([]string, error)
}

// ClamAVScanner is satisfied by clamav.Client.
type ClamAVScanner interface {
	ScanFile(path string) (infected bool, ruleName string, err error)
}

type Watcher struct {
	cfg        config.PatrolConfig
	db         *sql.DB
	log        events.Writer
	feed       ThreatChecker
	fsw        *fsnotify.Watcher
	pending    map[string]time.Time
	mu         sync.Mutex
	stopCh     chan struct{}
	ransomware *RansomwareDetector
	canary     *CanaryManager
	yara       FileDetector
	clam       ClamAVScanner
}

// ThreatChecker is satisfied by the threatfeed.Client.
type ThreatChecker interface {
	Check(hash string) (verdict string, source string, err error)
}

func NewWatcher(cfg config.PatrolConfig, db *sql.DB, log events.Writer,
	feed ThreatChecker, yara FileDetector, clam ClamAVScanner) (*Watcher, error) {

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	var rd *RansomwareDetector
	if cfg.Ransomware.Enabled {
		rd = NewRansomwareDetector(cfg.Ransomware, log)
	}

	var cm *CanaryManager
	if cfg.Canary.Enabled {
		cm = NewCanaryManager(log)
	}

	return &Watcher{
		cfg:        cfg,
		db:         db,
		log:        log,
		feed:       feed,
		fsw:        fsw,
		pending:    make(map[string]time.Time),
		stopCh:     make(chan struct{}),
		ransomware: rd,
		canary:     cm,
		yara:       yara,
		clam:       clam,
	}, nil
}

func (w *Watcher) Start() error {
	for _, path := range w.cfg.Scan.WatchPaths {
		if err := w.fsw.Add(path); err != nil {
			return err
		}
	}

	// Plant canary files in all watched directories
	if w.canary != nil {
		w.canary.PlantAll(w.cfg.Scan.WatchPaths)
	}

	go w.debounceLoop()
	go w.eventLoop()
	return nil
}

func (w *Watcher) Stop() {
	close(w.stopCh)
	w.fsw.Close()
	if w.canary != nil {
		w.canary.CleanupAll()
	}
}

func (w *Watcher) eventLoop() {
	for {
		select {
		case <-w.stopCh:
			return
		case evt, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			if w.excluded(evt.Name) {
				continue
			}

			// Canary check — highest priority
			if w.canary != nil && w.canary.IsCanary(evt.Name) {
				w.canary.Triggered(evt.Name)
				continue
			}

			if evt.Has(fsnotify.Create) || evt.Has(fsnotify.Write) || evt.Has(fsnotify.Rename) {
				// Ransomware detection
				if w.ransomware != nil {
					w.ransomware.Record(evt.Name)
				}
				w.mu.Lock()
				w.pending[evt.Name] = time.Now()
				w.mu.Unlock()
			}
			if evt.Has(fsnotify.Remove) {
				// Ransomware detection covers deletions too
				if w.ransomware != nil {
					w.ransomware.Record(evt.Name)
				}
				w.log.Write(events.New(events.SourcePatrol, "file_deleted", events.Warn,
					map[string]string{"path": evt.Name}))
			}
		case _, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
		}
	}
}

// debounceLoop drains the pending map every debounceWindow and processes files
// whose last event was at least debounceWindow ago.
func (w *Watcher) debounceLoop() {
	ticker := time.NewTicker(debounceWindow)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-debounceWindow)
			w.mu.Lock()
			ready := make([]string, 0)
			for path, t := range w.pending {
				if t.Before(cutoff) {
					ready = append(ready, path)
					delete(w.pending, path)
				}
			}
			w.mu.Unlock()

			for _, path := range ready {
				w.processFile(path)
			}
		}
	}
}

func (w *Watcher) processFile(path string) {
	hash, err := HashFile(path)
	if err != nil {
		return
	}

	// Compare against baseline
	row := w.db.QueryRow(`SELECT hash FROM file_baseline WHERE path=?`, path)
	var baseHash string
	newFile := false
	if err := row.Scan(&baseHash); err != nil {
		newFile = true
	}

	if newFile {
		w.log.Write(events.New(events.SourcePatrol, "new_file", events.Info,
			map[string]string{"path": path, "hash": hash}))
	} else if hash != baseHash {
		w.log.Write(events.New(events.SourcePatrol, "file_changed", events.Warn,
			map[string]string{"path": path, "old_hash": baseHash, "new_hash": hash}))
	} else {
		return // content unchanged despite fs event
	}

	// Async deep scan: threat feed + YARA + ClamAV + heuristics
	go w.deepScan(path, hash)
}

func (w *Watcher) deepScan(path, hash string) {
	// Threat feed
	if w.feed != nil {
		verdict, source, err := w.feed.Check(hash)
		if err == nil && verdict != "clean" {
			w.log.Write(events.New(events.SourcePatrol, "threat_detected", events.Critical,
				map[string]string{"path": path, "hash": hash, "verdict": verdict, "source": source}))
		}
	}

	// YARA
	if w.yara != nil {
		if matches, err := w.yara.ScanFile(path); err == nil && len(matches) > 0 {
			w.log.Write(events.New(events.SourcePatrol, "yara_match", events.Critical,
				map[string]string{"path": path, "rules": strings.Join(matches, ",")}))
		}
	}

	// ClamAV
	if w.clam != nil {
		if infected, rule, err := w.clam.ScanFile(path); err == nil && infected {
			w.log.Write(events.New(events.SourcePatrol, "clamav_match", events.Critical,
				map[string]string{"path": path, "rule": rule}))
		}
	}

	// Static heuristics (PE/ELF)
	if w.cfg.Heuristics.Enabled {
		score, reasons, severity := heuristics.AnalyzeFile(
			path,
			w.cfg.Heuristics.EntropyWarn,
			w.cfg.Heuristics.ScoreWarn,
			w.cfg.Heuristics.ScoreCritical,
		)
		if severity != "" {
			sev := events.Warn
			if severity == "critical" {
				sev = events.Critical
			}
			w.log.Write(events.New(events.SourcePatrol, "suspicious_file", sev,
				map[string]string{
					"path":    path,
					"score":   fmt.Sprintf("%d", score),
					"reasons": strings.Join(reasons, "; "),
				}))
		}
	}
}

func (w *Watcher) excluded(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, ex := range w.cfg.Scan.Exclude.Extensions {
		if ext == ex {
			return true
		}
	}
	for _, ex := range w.cfg.Scan.Exclude.Paths {
		if strings.HasPrefix(path, ex) {
			return true
		}
	}
	return false
}
