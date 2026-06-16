package db

import (
	"database/sql"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

func Open(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_timeout=5000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: single writer
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

	CREATE TABLE IF NOT EXISTS file_baseline (
		path        TEXT    NOT NULL PRIMARY KEY,
		hash        TEXT    NOT NULL,
		size        INTEGER NOT NULL,
		mtime       INTEGER NOT NULL,
		scanned_at  INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS folder_summary (
		folder      TEXT    NOT NULL PRIMARY KEY,
		file_count  INTEGER NOT NULL,
		total_bytes INTEGER NOT NULL,
		updated_at  INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS process_baseline (
		exe_path    TEXT    NOT NULL PRIMARY KEY,
		exe_hash    TEXT    NOT NULL,
		name        TEXT    NOT NULL,
		baselined_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS threat_cache (
		hash        TEXT    NOT NULL PRIMARY KEY,
		verdict     TEXT    NOT NULL,
		source      TEXT    NOT NULL,
		checked_at  INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS quarantine (
		id              TEXT    NOT NULL PRIMARY KEY,
		original_path   TEXT    NOT NULL,
		original_name   TEXT    NOT NULL,
		quarantine_time INTEGER NOT NULL,
		threat_info     TEXT    NOT NULL,
		verdict_source  TEXT    NOT NULL,
		encrypted       INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS guard_rules (
		id        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		type      TEXT    NOT NULL,
		process   TEXT,
		domain    TEXT,
		ip_cidr   TEXT,
		comment   TEXT,
		created_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS phishing_domains (
		domain      TEXT    NOT NULL PRIMARY KEY,
		added_at    INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS backup_hashes (
		path        TEXT    NOT NULL PRIMARY KEY,
		hash        TEXT    NOT NULL,
		size        INTEGER NOT NULL,
		mtime       INTEGER NOT NULL,
		backed_up_at INTEGER NOT NULL
	);
	`)
	return err
}
