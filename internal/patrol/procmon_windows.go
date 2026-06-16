//go:build windows

package patrol

import (
	"database/sql"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tpt-av/tpt-av/internal/events"
)

// ProcessMonitor on Windows polls the process list every 2 seconds and
// compares against the known baseline. A proper WMI subscription requires
// cgo; polling is lightweight enough for a security scanner.
type ProcessMonitor struct {
	db     *sql.DB
	log    events.Writer
	feed   ThreatChecker
	stopCh chan struct{}
	seen   map[string]string // exe_path → hash
}

func NewProcessMonitor(db *sql.DB, log events.Writer, feed ThreatChecker) *ProcessMonitor {
	return &ProcessMonitor{
		db:     db,
		log:    log,
		feed:   feed,
		stopCh: make(chan struct{}),
		seen:   make(map[string]string),
	}
}

func (pm *ProcessMonitor) Start() error {
	go pm.loop()
	return nil
}

func (pm *ProcessMonitor) Stop() {
	close(pm.stopCh)
}

func (pm *ProcessMonitor) loop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-pm.stopCh:
			return
		case <-ticker.C:
			pm.poll()
		}
	}
}

func (pm *ProcessMonitor) poll() {
	// Use WMIC to list running executables
	out, err := exec.Command("wmic", "process", "get", "ExecutablePath", "/format:csv").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.SplitN(line, ",", 2)
		if len(fields) < 2 {
			continue
		}
		exePath := strings.TrimSpace(fields[1])
		if exePath == "" || exePath == "ExecutablePath" {
			continue
		}

		if _, already := pm.seen[exePath]; already {
			continue
		}

		hash, err := HashFile(exePath)
		if err != nil {
			pm.seen[exePath] = "" // mark as seen even if unreadable
			continue
		}
		pm.seen[exePath] = hash

		name := filepath.Base(exePath)

		// Check baseline
		row := pm.db.QueryRow(`SELECT exe_hash FROM process_baseline WHERE exe_path=?`, exePath)
		var baseHash string
		if scanErr := row.Scan(&baseHash); scanErr != nil {
			pm.log.Write(events.New(events.SourcePatrol, "process_created", events.Info,
				map[string]string{"name": name, "exe": exePath, "hash": hash}))
		} else if hash != baseHash {
			pm.log.Write(events.New(events.SourcePatrol, "process_anomaly", events.Warn,
				map[string]string{
					"name": name, "exe": exePath,
					"old_hash": baseHash, "new_hash": hash,
				}))
			if pm.feed != nil {
				go func(p, h string) {
					verdict, source, err := pm.feed.Check(h)
					if err == nil && verdict != "clean" {
						pm.log.Write(events.New(events.SourcePatrol, "threat_detected", events.Critical,
							map[string]string{"path": p, "hash": h, "verdict": verdict, "source": source}))
					}
				}(exePath, hash)
			}
		}
	}
	_ = fmt.Sprintf // keep fmt import used
}
