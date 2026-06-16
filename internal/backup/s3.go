package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// S3Client uploads files to a Wasabi (or any S3-compatible) bucket.
// Uses AWS Signature V4 directly — no external SDK required.
// Files are AES-256-GCM encrypted client-side before upload when a passphrase is set.
type S3Client struct {
	endpoint  string
	bucket    string
	accessKey string
	secretKey string
	region    string
	passKey   []byte // 32-byte AES key derived from passphrase; nil = no encryption
	db        *sql.DB
	http      *http.Client
}

func NewS3Client(endpoint, bucket, accessKey, secretKey, region, passphrase string, db *sql.DB) *S3Client {
	var passKey []byte
	if passphrase != "" {
		sum := sha256.Sum256([]byte(passphrase))
		passKey = sum[:]
	}
	if region == "" {
		region = "us-east-1"
	}
	return &S3Client{
		endpoint:  endpoint,
		bucket:    bucket,
		accessKey: accessKey,
		secretKey: secretKey,
		region:    region,
		passKey:   passKey,
		db:        db,
		http:      &http.Client{Timeout: 5 * time.Minute},
	}
}

// UploadChanged walks source paths and uploads files whose hash has changed since last run.
func (c *S3Client) UploadChanged(sources []string) error {
	for _, src := range sources {
		if err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			return c.uploadIfChanged(path, info)
		}); err != nil {
			return fmt.Errorf("walk %s: %w", src, err)
		}
	}
	return nil
}

func (c *S3Client) uploadIfChanged(path string, info os.FileInfo) error {
	hash, err := hashFile(path)
	if err != nil {
		return nil // skip unreadable files
	}

	// Check DB to see if the file has changed
	row := c.db.QueryRow(`SELECT hash FROM backup_hashes WHERE path=?`, path)
	var prevHash string
	if row.Scan(&prevHash) == nil && prevHash == hash {
		return nil // unchanged
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Encrypt if passphrase is set
	if c.passKey != nil {
		data, err = encrypt(data, c.passKey)
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", path, err)
		}
	}

	key := s3Key(path)
	if err := c.putObject(key, data); err != nil {
		return fmt.Errorf("upload %s: %w", path, err)
	}

	// Update hash record
	c.db.Exec(`
		INSERT INTO backup_hashes(path, hash, size, mtime, backed_up_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(path) DO UPDATE SET
			hash=excluded.hash, size=excluded.size,
			mtime=excluded.mtime, backed_up_at=excluded.backed_up_at`,
		path, hash, info.Size(), info.ModTime().Unix(), time.Now().Unix())

	return nil
}

func (c *S3Client) putObject(key string, data []byte) error {
	host := fmt.Sprintf("%s.%s", c.bucket, c.endpoint)
	urlStr := fmt.Sprintf("https://%s/%s", host, key)

	now := time.Now().UTC()
	dateISO := now.Format("20060102T150405Z")
	dateShort := now.Format("20060102")

	bodyHash := hashBytes(data)

	req, err := http.NewRequest("PUT", urlStr, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Host", host)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("x-amz-date", dateISO)
	req.Header.Set("x-amz-content-sha256", bodyHash)

	// AWS Signature V4
	sig := c.signV4(req, dateShort, dateISO, bodyHash, data)
	req.Header.Set("Authorization", sig)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated &&
		resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("S3 PUT %s: HTTP %d: %s", key, resp.StatusCode, body)
	}
	return nil
}

// signV4 generates the AWS Signature V4 Authorization header value.
func (c *S3Client) signV4(req *http.Request, dateShort, dateISO, bodyHash string, _ []byte) string {
	// Canonical request
	signedHeaders := "content-type;host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := fmt.Sprintf(
		"content-type:%s\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		req.Header.Get("Content-Type"),
		req.Header.Get("Host"),
		bodyHash,
		dateISO,
	)
	canonicalReq := strings.Join([]string{
		req.Method,
		"/" + strings.TrimPrefix(req.URL.Path, "/"),
		"",
		canonicalHeaders,
		signedHeaders,
		bodyHash,
	}, "\n")

	credentialScope := dateShort + "/" + c.region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		dateISO,
		credentialScope,
		hashString(canonicalReq),
	}, "\n")

	signingKey := hmacSHA256(
		hmacSHA256(
			hmacSHA256(
				hmacSHA256([]byte("AWS4"+c.secretKey), []byte(dateShort)),
				[]byte(c.region),
			),
			[]byte("s3"),
		),
		[]byte("aws4_request"),
	)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	return fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.accessKey, credentialScope, signedHeaders, signature,
	)
}

// ─── Encryption helpers ───────────────────────────────────────────────────────

// encrypt encrypts plaintext with AES-256-GCM. The nonce is prepended to the ciphertext.
func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// ─── Hashing helpers ─────────────────────────────────────────────────────────

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hashString(s string) string {
	return hashBytes([]byte(s))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// s3Key converts a local absolute path to an S3 object key (forward slashes, no drive letter).
func s3Key(path string) string {
	// Remove drive letter on Windows (C:\foo → foo)
	if len(path) >= 2 && path[1] == ':' {
		path = path[2:]
	}
	key := strings.ReplaceAll(path, "\\", "/")
	key = strings.TrimPrefix(key, "/")
	return key
}
