//go:build !yara

// Package yara provides YARA rule scanning. Build with -tags yara to enable
// (requires libyara and CGo). Without the tag, Scanner is a no-op stub.
package yara

// Scanner is a no-op YARA scanner used when the yara build tag is absent.
type Scanner struct{}

func NewScanner(rulesDir string) (*Scanner, error) { return &Scanner{}, nil }
func (s *Scanner) ScanFile(path string) ([]string, error) { return nil, nil }
func (s *Scanner) ScanBytes(data []byte) ([]string, error) { return nil, nil }
func (s *Scanner) Reload() error                           { return nil }
func (s *Scanner) Close()                                  {}
