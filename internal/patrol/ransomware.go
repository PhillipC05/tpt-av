package patrol

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/tpt-av/tpt-av/internal/config"
	"github.com/tpt-av/tpt-av/internal/events"
)

// RansomwareDetector watches for mass file changes in a directory within a sliding
// time window — a common indicator of ransomware encrypting files.
type RansomwareDetector struct {
	threshold int
	window    time.Duration
	log       events.Writer
	mu        sync.Mutex
	// dirEvents maps directory path → list of event timestamps
	dirEvents map[string][]time.Time
	// alerted tracks directories that have already fired an alert this window
	alerted map[string]time.Time
}

func NewRansomwareDetector(cfg config.RansomwareConfig, log events.Writer) *RansomwareDetector {
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = 20
	}
	windowSec := cfg.WindowSeconds
	if windowSec <= 0 {
		windowSec = 30
	}
	return &RansomwareDetector{
		threshold: threshold,
		window:    time.Duration(windowSec) * time.Second,
		log:       log,
		dirEvents: make(map[string][]time.Time),
		alerted:   make(map[string]time.Time),
	}
}

// Record registers a file modification event. Returns true if the ransomware
// threshold was just crossed for the containing directory.
func (d *RansomwareDetector) Record(path string) bool {
	dir := filepath.Dir(path)
	now := time.Now()
	cutoff := now.Add(-d.window)

	d.mu.Lock()
	defer d.mu.Unlock()

	// Prune events older than the window
	evts := d.dirEvents[dir]
	fresh := evts[:0]
	for _, t := range evts {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, now)
	d.dirEvents[dir] = fresh

	if len(fresh) < d.threshold {
		return false
	}

	// Avoid repeated alerts for the same directory within the same window
	if last, ok := d.alerted[dir]; ok && now.Sub(last) < d.window {
		return false
	}
	d.alerted[dir] = now

	d.log.Write(events.New(events.SourcePatrol, "ransomware_detected", events.Critical,
		map[string]string{
			"directory": dir,
			"files":     itoa(len(fresh)),
			"window_s":  itoa(int(d.window.Seconds())),
		}))
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte(n%10) + '0'
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
