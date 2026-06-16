package patrol

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/tpt-av/tpt-av/internal/config"
	"github.com/tpt-av/tpt-av/internal/events"
	"github.com/tpt-av/tpt-av/internal/heuristics"
)

type Scanner struct {
	cfg      config.PatrolConfig
	db       *sql.DB
	log      events.Writer
	feed     ThreatChecker
	yara     FileDetector
	clam     ClamAVScanner
	c        *cron.Cron
	LastScan time.Time
}

func NewScanner(cfg config.PatrolConfig, db *sql.DB, log events.Writer,
	feed ThreatChecker, yara FileDetector, clam ClamAVScanner) *Scanner {
	return &Scanner{cfg: cfg, db: db, log: log, feed: feed, yara: yara, clam: clam}
}

func (s *Scanner) Start() error {
	s.c = cron.New()

	schedule := s.cfg.Scan.Schedule
	if schedule == "" {
		schedule = "0 */6 * * *"
	}

	_, err := s.c.AddFunc(schedule, func() {
		if !s.inWindow() {
			return
		}
		s.runScan()
	})
	if err != nil {
		return fmt.Errorf("invalid cron schedule %q: %w", schedule, err)
	}

	s.c.Start()
	return nil
}

func (s *Scanner) Stop() {
	if s.c != nil {
		s.c.Stop()
	}
}

// RunNow triggers an immediate scan outside the normal cron schedule.
func (s *Scanner) RunNow() {
	go s.runScan()
}

// BaselineStats returns a summary of the current file-integrity baseline.
func (s *Scanner) BaselineStats() (BaselineStats, error) {
	return GetBaselineStats(s.db)
}

// RebuildBaseline re-hashes every file under the configured paths and rewrites
// the baseline from scratch. Runs asynchronously at below-normal priority.
func (s *Scanner) RebuildBaseline() {
	go func() {
		setPriority() // platform-specific: below-normal OS thread priority
		start := time.Now()
		if err := BuildBaseline(s.db, s.cfg.Scan.BaselinePaths, s.cfg.Scan.Exclude, s.log, s.cfg.Scan.BatchDelayMS); err != nil {
			s.log.Write(events.New(events.SourcePatrol, "baseline_error", events.Warn,
				map[string]string{"error": err.Error()}))
			return
		}
		s.LastScan = time.Now()
		s.log.Write(events.New(events.SourcePatrol, "baseline_rebuilt", events.Info,
			map[string]string{
				"duration_ms": fmt.Sprintf("%d", time.Since(start).Milliseconds()),
				"paths":       fmt.Sprintf("%d", len(s.cfg.Scan.BaselinePaths)),
			}))
	}()
}

func (s *Scanner) runScan() {
	setPriority() // platform-specific: below-normal OS thread priority

	start := time.Now()
	var totalChanged int

	for _, root := range s.cfg.Scan.BaselinePaths {
		dirty, err := FolderDirty(s.db, root, s.cfg.Scan.Exclude)
		if err != nil || !dirty {
			continue // quick-skip: folder unchanged
		}
		changed, err := ScanChanged(s.db, root, s.cfg.Scan.Exclude, s.log, s.cfg.Scan.BatchDelayMS)
		if err != nil {
			continue
		}
		if len(changed) > 0 {
			UpdateBaseline(s.db, changed)
			totalChanged += len(changed)

			// Async deep scan for each changed file
			for _, rec := range changed {
				go s.deepScan(rec)
			}
		}
	}

	s.LastScan = time.Now()
	s.log.Write(events.New(events.SourcePatrol, "scan_complete", events.Info,
		map[string]string{
			"duration_ms":   fmt.Sprintf("%d", time.Since(start).Milliseconds()),
			"files_changed": fmt.Sprintf("%d", totalChanged),
		}))
}

func (s *Scanner) deepScan(rec FileRecord) {
	if s.feed != nil {
		verdict, source, err := s.feed.Check(rec.Hash)
		if err == nil && verdict != "clean" {
			s.log.Write(events.New(events.SourcePatrol, "threat_detected", events.Critical,
				map[string]string{"path": rec.Path, "hash": rec.Hash, "verdict": verdict, "source": source}))
		}
	}

	if s.yara != nil {
		if matches, err := s.yara.ScanFile(rec.Path); err == nil && len(matches) > 0 {
			s.log.Write(events.New(events.SourcePatrol, "yara_match", events.Critical,
				map[string]string{"path": rec.Path, "rules": strings.Join(matches, ",")}))
		}
	}

	if s.clam != nil {
		if infected, rule, err := s.clam.ScanFile(rec.Path); err == nil && infected {
			s.log.Write(events.New(events.SourcePatrol, "clamav_match", events.Critical,
				map[string]string{"path": rec.Path, "rule": rule}))
		}
	}

	if s.cfg.Heuristics.Enabled {
		score, reasons, severity := heuristics.AnalyzeFile(
			rec.Path,
			s.cfg.Heuristics.EntropyWarn,
			s.cfg.Heuristics.ScoreWarn,
			s.cfg.Heuristics.ScoreCritical,
		)
		if severity != "" {
			sev := events.Warn
			if severity == "critical" {
				sev = events.Critical
			}
			s.log.Write(events.New(events.SourcePatrol, "suspicious_file", sev,
				map[string]string{
					"path":    rec.Path,
					"score":   fmt.Sprintf("%d", score),
					"reasons": strings.Join(reasons, "; "),
				}))
		}
	}
}

// inWindow returns true when the current time falls within the configured
// scan_window (e.g. "02:00-05:00"). Empty window means always allowed.
func (s *Scanner) inWindow() bool {
	window := s.cfg.Scan.Window
	if window == "" {
		return true
	}
	var startH, startM, endH, endM int
	if _, err := fmt.Sscanf(window, "%d:%d-%d:%d", &startH, &startM, &endH, &endM); err != nil {
		return true // malformed window → don't block scans
	}
	now := time.Now()
	h, m := now.Hour(), now.Minute()
	cur := h*60 + m
	start := startH*60 + startM
	end := endH*60 + endM
	if start <= end {
		return cur >= start && cur < end
	}
	// wraps midnight
	return cur >= start || cur < end
}
