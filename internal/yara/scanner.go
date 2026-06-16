//go:build yara

// Package yara wraps go-yara/v4 for event-driven file scanning.
// Build with: CGO_ENABLED=1 go build -tags yara
// Requires: libyara-dev (Linux: apt install libyara-dev / apk add yara-dev)
package yara

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hillu/go-yara/v4"
)

// Scanner compiles YARA rules from a directory and provides file/bytes scanning.
// Rules are hot-reloaded via Reload() when the rules directory changes.
type Scanner struct {
	rulesDir string
	mu       sync.RWMutex
	compiled *yara.Rules
}

func NewScanner(rulesDir string) (*Scanner, error) {
	s := &Scanner{rulesDir: rulesDir}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload recompiles all .yar and .yara files from the rules directory.
func (s *Scanner) Reload() error {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("yara compiler: %w", err)
	}

	entries, err := os.ReadDir(s.rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no rules yet — not an error
		}
		return err
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yar") && !strings.HasSuffix(name, ".yara") {
			continue
		}
		f, err := os.Open(filepath.Join(s.rulesDir, name))
		if err != nil {
			continue
		}
		compiler.AddFile(f, name)
		f.Close()
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return fmt.Errorf("yara compile: %w", err)
	}

	s.mu.Lock()
	s.compiled = rules
	s.mu.Unlock()
	return nil
}

// ScanFile scans a file path and returns matched rule names.
func (s *Scanner) ScanFile(path string) ([]string, error) {
	s.mu.RLock()
	rules := s.compiled
	s.mu.RUnlock()
	if rules == nil {
		return nil, nil
	}

	var matches yara.MatchRules
	if err := rules.ScanFile(path, 0, 0, &matches); err != nil {
		return nil, err
	}
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = m.Rule
	}
	return names, nil
}

// ScanBytes scans an in-memory buffer and returns matched rule names.
func (s *Scanner) ScanBytes(data []byte) ([]string, error) {
	s.mu.RLock()
	rules := s.compiled
	s.mu.RUnlock()
	if rules == nil {
		return nil, nil
	}

	var matches yara.MatchRules
	if err := rules.ScanMem(data, 0, 0, &matches); err != nil {
		return nil, err
	}
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = m.Rule
	}
	return names, nil
}

func (s *Scanner) Close() {
	s.mu.Lock()
	s.compiled = nil
	s.mu.Unlock()
}
