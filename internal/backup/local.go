package backup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// LocalBackup copies source paths to a timestamped snapshot directory and prunes
// old snapshots to the configured retain count.
type LocalBackup struct {
	dest   string
	retain int
}

func NewLocalBackup(dest string, retain int) *LocalBackup {
	if retain <= 0 {
		retain = 7
	}
	return &LocalBackup{dest: dest, retain: retain}
}

// Run creates a new snapshot of all sources and prunes old ones.
func (b *LocalBackup) Run(sources []string) error {
	snap := filepath.Join(b.dest, time.Now().Format("2006-01-02_15-04"))
	if err := os.MkdirAll(snap, 0o755); err != nil {
		return fmt.Errorf("create snapshot dir: %w", err)
	}

	for _, src := range sources {
		dst := filepath.Join(snap, filepath.Base(src))
		if err := copyDir(src, dst); err != nil {
			return fmt.Errorf("copy %s: %w", src, err)
		}
	}

	return b.prune()
}

func (b *LocalBackup) prune() error {
	entries, err := os.ReadDir(b.dest)
	if err != nil {
		return err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	for len(dirs) > b.retain {
		oldest := filepath.Join(b.dest, dirs[0])
		if err := os.RemoveAll(oldest); err != nil {
			return err
		}
		dirs = dirs[1:]
	}
	return nil
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return copyFile(src, dst)
	}

	if err := os.MkdirAll(dst, info.Mode()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := copyDir(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
