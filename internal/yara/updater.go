// Package yara — rule set auto-updater. Works regardless of build tag.
package yara

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// ruleSource describes a remote YARA rule file to download.
type ruleSource struct {
	name string
	url  string
}

// Community rule sets (raw GitHub URLs — no auth needed).
var defaultSources = []ruleSource{
	{
		name: "yara-rules-index.yar",
		url:  "https://raw.githubusercontent.com/Yara-Rules/rules/master/index.yar",
	},
	{
		name: "neo23x0-generic.yar",
		url:  "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_webshells.yar",
	},
	{
		name: "neo23x0-mal.yar",
		url:  "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/mal_ransom_generic.yar",
	},
}

// Updater downloads community YARA rule sets to a local directory and triggers
// Scanner.Reload() on success. Falls back to cached rules if any download fails.
type Updater struct {
	rulesDir string
	scanner  *Scanner
	http     *http.Client
}

func NewUpdater(rulesDir string, scanner *Scanner) *Updater {
	return &Updater{
		rulesDir: rulesDir,
		scanner:  scanner,
		http:     &http.Client{Timeout: 60 * time.Second},
	}
}

// Update downloads all rule sources. Returns the number successfully updated.
func (u *Updater) Update() (int, error) {
	if err := os.MkdirAll(u.rulesDir, 0o750); err != nil {
		return 0, fmt.Errorf("rules dir: %w", err)
	}

	updated := 0
	var lastErr error
	for _, src := range defaultSources {
		if err := u.fetch(src); err != nil {
			lastErr = err
			continue
		}
		updated++
	}

	if updated > 0 && u.scanner != nil {
		u.scanner.Reload()
	}

	if updated == 0 && lastErr != nil {
		return 0, fmt.Errorf("all YARA rule downloads failed; last: %w", lastErr)
	}
	return updated, nil
}

func (u *Updater) fetch(src ruleSource) error {
	resp, err := u.http.Get(src.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, src.url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 8 MB cap
	if err != nil {
		return err
	}

	dest := filepath.Join(u.rulesDir, src.name)
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, body, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}
