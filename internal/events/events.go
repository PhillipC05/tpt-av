package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Severity string

const (
	Debug    Severity = "debug"
	Info     Severity = "info"
	Warn     Severity = "warn"
	Critical Severity = "critical"
)

type Source string

const (
	SourceGuard  Source = "guard"
	SourcePatrol Source = "patrol"
)

type Event struct {
	TS       time.Time         `json:"ts"`
	Source   Source            `json:"source"`
	Type     string            `json:"type"`
	Severity Severity          `json:"severity"`
	Data     map[string]string `json:"data,omitempty"`
}

type Logger struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func NewLogger(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	return &Logger{path: path, f: f}, nil
}

func (l *Logger) Write(e Event) error {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b = append(b, '\n')
	_, err = l.f.Write(b)
	return err
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// ReadAll reads every event from the log file. For large logs use ReadSince.
func ReadAll(path string) ([]Event, error) {
	return ReadSince(path, time.Time{})
}

// ReadSince returns events with TS after the given time.
func ReadSince(path string, since time.Time) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var events []Event
	dec := json.NewDecoder(f)
	for dec.More() {
		var e Event
		if err := dec.Decode(&e); err != nil {
			continue // skip malformed lines
		}
		if since.IsZero() || e.TS.After(since) {
			events = append(events, e)
		}
	}
	return events, nil
}

// Writer is a minimal interface for writing events. Components accept Writer
// instead of *Logger so that wrappers (e.g. alert/quarantine decorators) can
// intercept writes without breaking the concrete type.
type Writer interface {
	Write(Event) error
}

// ─── Convenience constructors ─────────────────────────────────────────────────

func New(source Source, typ string, sev Severity, data map[string]string) Event {
	return Event{
		TS:       time.Now().UTC(),
		Source:   source,
		Type:     typ,
		Severity: sev,
		Data:     data,
	}
}
