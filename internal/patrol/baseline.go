package patrol

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tpt-av/tpt-av/internal/config"
	"github.com/tpt-av/tpt-av/internal/events"
)

type FileRecord struct {
	Path      string
	Hash      string
	Size      int64
	Mtime     time.Time
	ScannedAt time.Time
}

// HashFile computes the SHA-256 of a file.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// BuildBaseline walks dirs and records every file's hash in SQLite.
func BuildBaseline(db *sql.DB, paths []string, excl config.ExcludeConfig, log events.Writer, delayMS int) error {
	for _, root := range paths {
		if err := walkDir(db, root, excl, log, delayMS); err != nil {
			return err
		}
	}
	return nil
}

func walkDir(db *sql.DB, root string, excl config.ExcludeConfig, log events.Writer, delayMS int) error {
	var fileCount int64
	var totalBytes int64

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			for _, ex := range excl.Paths {
				if strings.HasPrefix(path, ex) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		// Skip excluded extensions
		ext := strings.ToLower(filepath.Ext(path))
		for _, ex := range excl.Extensions {
			if ext == ex {
				return nil
			}
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		hash, err := HashFile(path)
		if err != nil {
			return nil
		}

		now := time.Now().Unix()
		_, err = db.Exec(`
			INSERT INTO file_baseline(path, hash, size, mtime, scanned_at)
			VALUES(?,?,?,?,?)
			ON CONFLICT(path) DO UPDATE SET
				hash=excluded.hash, size=excluded.size,
				mtime=excluded.mtime, scanned_at=excluded.scanned_at`,
			path, hash, info.Size(), info.ModTime().Unix(), now)
		if err != nil {
			return err
		}

		fileCount++
		totalBytes += info.Size()

		if delayMS > 0 {
			time.Sleep(time.Duration(delayMS) * time.Millisecond)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Update folder summary
	_, err = db.Exec(`
		INSERT INTO folder_summary(folder, file_count, total_bytes, updated_at)
		VALUES(?,?,?,?)
		ON CONFLICT(folder) DO UPDATE SET
			file_count=excluded.file_count,
			total_bytes=excluded.total_bytes,
			updated_at=excluded.updated_at`,
		root, fileCount, totalBytes, time.Now().Unix())
	return err
}

// FolderStat summarises one watched folder's baseline.
type FolderStat struct {
	Folder     string `json:"folder"`
	FileCount  int64  `json:"file_count"`
	TotalBytes int64  `json:"total_bytes"`
	UpdatedAt  int64  `json:"updated_at"`
}

// BaselineStats summarises the whole file-integrity baseline.
type BaselineStats struct {
	Files      int64        `json:"files"`
	TotalBytes int64        `json:"total_bytes"`
	Folders    []FolderStat `json:"folders"`
}

// GetBaselineStats returns a summary of the current baseline: total file count,
// total bytes, and a per-folder breakdown from the folder_summary table.
func GetBaselineStats(db *sql.DB) (BaselineStats, error) {
	var st BaselineStats
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size),0) FROM file_baseline`).
		Scan(&st.Files, &st.TotalBytes); err != nil {
		return st, err
	}

	rows, err := db.Query(`SELECT folder, file_count, total_bytes, updated_at FROM folder_summary ORDER BY folder`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var f FolderStat
		if err := rows.Scan(&f.Folder, &f.FileCount, &f.TotalBytes, &f.UpdatedAt); err != nil {
			return st, err
		}
		st.Folders = append(st.Folders, f)
	}
	return st, rows.Err()
}

// FolderDirty returns true if a directory's file count or total size has
// changed since the last baseline — the quick pre-check before hashing.
func FolderDirty(db *sql.DB, root string, excl config.ExcludeConfig) (bool, error) {
	row := db.QueryRow(`SELECT file_count, total_bytes FROM folder_summary WHERE folder=?`, root)
	var baselineCount, baselineBytes int64
	if err := row.Scan(&baselineCount, &baselineBytes); err != nil {
		if err == sql.ErrNoRows {
			return true, nil // no baseline yet → treat as dirty
		}
		return false, err
	}

	var liveCount, liveBytes int64
	filepath.WalkDir(root, func(path string, d os.DirEntry, _ error) error {
		if d == nil {
			return nil
		}
		if d.IsDir() {
			for _, ex := range excl.Paths {
				if strings.HasPrefix(path, ex) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		for _, ex := range excl.Extensions {
			if ext == ex {
				return nil
			}
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		liveCount++
		liveBytes += info.Size()
		return nil
	})

	return liveCount != baselineCount || liveBytes != baselineBytes, nil
}

// ScanChanged hashes only files whose mtime or size differ from the baseline.
func ScanChanged(db *sql.DB, root string, excl config.ExcludeConfig, log events.Writer, delayMS int) ([]FileRecord, error) {
	var changed []FileRecord

	filepath.WalkDir(root, func(path string, d os.DirEntry, _ error) error {
		if d == nil {
			return nil
		}
		if d.IsDir() {
			for _, ex := range excl.Paths {
				if strings.HasPrefix(path, ex) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		for _, ex := range excl.Extensions {
			if ext == ex {
				return nil
			}
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		row := db.QueryRow(`SELECT hash, size, mtime FROM file_baseline WHERE path=?`, path)
		var baseHash string
		var baseSize, baseMtime int64
		newFile := false
		if err := row.Scan(&baseHash, &baseSize, &baseMtime); err != nil {
			if err == sql.ErrNoRows {
				newFile = true
			} else {
				return nil
			}
		}

		mtimeChanged := info.ModTime().Unix() != baseMtime
		sizeChanged := info.Size() != baseSize

		if !newFile && !mtimeChanged && !sizeChanged {
			return nil // file is clean
		}

		hash, err := HashFile(path)
		if err != nil {
			return nil
		}

		rec := FileRecord{
			Path:      path,
			Hash:      hash,
			Size:      info.Size(),
			Mtime:     info.ModTime(),
			ScannedAt: time.Now(),
		}
		changed = append(changed, rec)

		// Emit event
		if newFile {
			log.Write(events.New(events.SourcePatrol, "new_file", events.Info, map[string]string{
				"path": path, "hash": hash,
			}))
		} else if hash != baseHash {
			log.Write(events.New(events.SourcePatrol, "file_changed", events.Warn, map[string]string{
				"path": path, "old_hash": baseHash, "new_hash": hash,
			}))
		}

		if delayMS > 0 {
			time.Sleep(time.Duration(delayMS) * time.Millisecond)
		}
		return nil
	})

	return changed, nil
}

// UpdateBaseline writes scanned records back to SQLite.
func UpdateBaseline(db *sql.DB, records []FileRecord) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO file_baseline(path, hash, size, mtime, scanned_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(path) DO UPDATE SET
			hash=excluded.hash, size=excluded.size,
			mtime=excluded.mtime, scanned_at=excluded.scanned_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range records {
		if _, err := stmt.Exec(r.Path, r.Hash, r.Size, r.Mtime.Unix(), r.ScannedAt.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
