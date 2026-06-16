package quarantine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/tpt-av/tpt-av/internal/config"
)

type Record struct {
	ID             string
	OriginalPath   string
	OriginalName   string
	QuarantineTime time.Time
	ThreatInfo     string
	VerdictSource  string
	Encrypted      bool
}

type Manager struct {
	cfg config.QuarantineConfig
	db  *sql.DB
	key []byte // 32-byte AES-256 key, derived from a stable secret
}

func New(cfg config.QuarantineConfig, db *sql.DB) (*Manager, error) {
	if err := os.MkdirAll(cfg.Path, 0o700); err != nil {
		return nil, err
	}
	m := &Manager{cfg: cfg, db: db}
	if cfg.Encrypt {
		key, err := loadOrGenerateKey(cfg.Path)
		if err != nil {
			return nil, fmt.Errorf("quarantine key: %w", err)
		}
		m.key = key
	}
	return m, nil
}

// Quarantine moves a file into the quarantine directory, optionally encrypts it,
// and records the action in SQLite.
func (m *Manager) Quarantine(path, threatInfo, verdictSource string) (string, error) {
	id := uuid.New().String()
	destName := id + ".quarantine"
	dest := filepath.Join(m.cfg.Path, destName)

	if m.cfg.Encrypt && m.key != nil {
		if err := encryptMove(path, dest, m.key); err != nil {
			return "", fmt.Errorf("encrypt quarantine: %w", err)
		}
	} else {
		if err := os.Rename(path, dest); err != nil {
			// Cross-device: copy then remove
			if err2 := copyFile(path, dest); err2 != nil {
				return "", fmt.Errorf("quarantine copy: %w", err2)
			}
			os.Remove(path)
		}
	}

	_, err := m.db.Exec(`
		INSERT INTO quarantine(id, original_path, original_name, quarantine_time, threat_info, verdict_source, encrypted)
		VALUES(?,?,?,?,?,?,?)`,
		id, path, filepath.Base(path), time.Now().Unix(), threatInfo, verdictSource, boolInt(m.cfg.Encrypt))
	if err != nil {
		return "", err
	}
	return id, nil
}

// Restore moves a quarantined file back to its original path.
func (m *Manager) Restore(id string) error {
	rec, err := m.Get(id)
	if err != nil {
		return err
	}

	src := filepath.Join(m.cfg.Path, id+".quarantine")
	if err := os.MkdirAll(filepath.Dir(rec.OriginalPath), 0o755); err != nil {
		return err
	}

	if rec.Encrypted && m.key != nil {
		if err := decryptMove(src, rec.OriginalPath, m.key); err != nil {
			return fmt.Errorf("decrypt restore: %w", err)
		}
	} else {
		if err := os.Rename(src, rec.OriginalPath); err != nil {
			if err2 := copyFile(src, rec.OriginalPath); err2 != nil {
				return fmt.Errorf("restore copy: %w", err2)
			}
			os.Remove(src)
		}
	}

	_, err = m.db.Exec(`DELETE FROM quarantine WHERE id=?`, id)
	return err
}

// Delete permanently removes a quarantined file.
func (m *Manager) Delete(id string) error {
	src := filepath.Join(m.cfg.Path, id+".quarantine")
	os.Remove(src)
	_, err := m.db.Exec(`DELETE FROM quarantine WHERE id=?`, id)
	return err
}

// List returns all quarantined file records.
func (m *Manager) List() ([]Record, error) {
	rows, err := m.db.Query(`
		SELECT id, original_path, original_name, quarantine_time, threat_info, verdict_source, encrypted
		FROM quarantine ORDER BY quarantine_time DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		var r Record
		var qt int64
		var enc int
		if err := rows.Scan(&r.ID, &r.OriginalPath, &r.OriginalName, &qt, &r.ThreatInfo, &r.VerdictSource, &enc); err != nil {
			continue
		}
		r.QuarantineTime = time.Unix(qt, 0)
		r.Encrypted = enc == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func (m *Manager) Get(id string) (*Record, error) {
	row := m.db.QueryRow(`
		SELECT id, original_path, original_name, quarantine_time, threat_info, verdict_source, encrypted
		FROM quarantine WHERE id=?`, id)
	var r Record
	var qt int64
	var enc int
	if err := row.Scan(&r.ID, &r.OriginalPath, &r.OriginalName, &qt, &r.ThreatInfo, &r.VerdictSource, &enc); err != nil {
		return nil, err
	}
	r.QuarantineTime = time.Unix(qt, 0)
	r.Encrypted = enc == 1
	return &r, nil
}

// ─── Crypto helpers ──────────────────────────────────────────────────────────

// loadOrGenerateKey reads the persisted AES-256 key from disk, or generates and
// saves a new random one if it does not exist. The key file lives inside the
// quarantine directory (mode 0o600) so it inherits the directory's 0o700 protection.
func loadOrGenerateKey(quarantineDir string) ([]byte, error) {
	keyPath := filepath.Join(quarantineDir, ".tpt-qkey")
	if data, err := os.ReadFile(keyPath); err == nil && len(data) == 32 {
		return data, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptMove(src, dst string, key []byte) error {
	plain, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nonce, nonce, plain, nil)

	if err := os.WriteFile(dst, ciphertext, 0o600); err != nil {
		return err
	}
	return os.Remove(src)
}

func decryptMove(src, dst string, key []byte) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}
	plain, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, plain, 0o644); err != nil {
		return err
	}
	return os.Remove(src)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
