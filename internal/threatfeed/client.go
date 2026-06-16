package threatfeed

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tpt-av/tpt-av/internal/config"
)

type Client struct {
	cfg    config.ThreatFeedConfig
	db     *sql.DB
	http   *http.Client
	cacheTTL time.Duration
}

func New(cfg config.ThreatFeedConfig, db *sql.DB) (*Client, error) {
	ttl, err := time.ParseDuration(cfg.CacheTTL)
	if err != nil {
		ttl = 168 * time.Hour // default 7 days
	}
	return &Client{
		cfg:      cfg,
		db:       db,
		http:     &http.Client{Timeout: 10 * time.Second},
		cacheTTL: ttl,
	}, nil
}

// Check returns (verdict, source, error).
// verdict is one of: "clean", "malicious", "suspicious", "unknown"
func (c *Client) Check(hash string) (string, string, error) {
	hash = strings.ToLower(hash)

	// Check local cache first
	if verdict, source, ok := c.fromCache(hash); ok {
		return verdict, source, nil
	}

	// Try MalwareBazaar
	if c.cfg.MalwareBazaar {
		verdict, err := c.checkMalwareBazaar(hash)
		if err == nil {
			c.cacheResult(hash, verdict, "malwarebazaar")
			return verdict, "malwarebazaar", nil
		}
	}

	// Try VirusTotal
	if c.cfg.VirusTotalKey != "" {
		verdict, err := c.checkVirusTotal(hash)
		if err == nil {
			c.cacheResult(hash, verdict, "virustotal")
			return verdict, "virustotal", nil
		}
	}

	return "unknown", "", nil
}

func (c *Client) fromCache(hash string) (verdict, source string, ok bool) {
	row := c.db.QueryRow(`SELECT verdict, source, checked_at FROM threat_cache WHERE hash=?`, hash)
	var checkedAt int64
	if err := row.Scan(&verdict, &source, &checkedAt); err != nil {
		return "", "", false
	}
	if time.Since(time.Unix(checkedAt, 0)) > c.cacheTTL {
		return "", "", false // expired
	}
	return verdict, source, true
}

func (c *Client) cacheResult(hash, verdict, source string) {
	c.db.Exec(`
		INSERT INTO threat_cache(hash, verdict, source, checked_at)
		VALUES(?,?,?,?)
		ON CONFLICT(hash) DO UPDATE SET
			verdict=excluded.verdict, source=excluded.source, checked_at=excluded.checked_at`,
		hash, verdict, source, time.Now().Unix())
}

// ─── MalwareBazaar ───────────────────────────────────────────────────────────

type mbResponse struct {
	QueryStatus string `json:"query_status"`
}

func (c *Client) checkMalwareBazaar(hash string) (string, error) {
	body := strings.NewReader("query=get_info&hash=" + hash)
	req, err := http.NewRequest("POST", "https://mb-api.abuse.ch/api/v1/", body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result mbResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	switch result.QueryStatus {
	case "ok":
		return "malicious", nil
	case "hash_not_found":
		return "clean", nil
	default:
		return "", fmt.Errorf("malwarebazaar: unexpected status %q", result.QueryStatus)
	}
}

// ─── VirusTotal ───────────────────────────────────────────────────────────────

type vtResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

func (c *Client) checkVirusTotal(hash string) (string, error) {
	url := "https://www.virustotal.com/api/v3/files/" + hash
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("x-apikey", c.cfg.VirusTotalKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "clean", nil
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("virustotal: HTTP %d", resp.StatusCode)
	}

	var result vtResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	stats := result.Data.Attributes.LastAnalysisStats
	if stats.Malicious > 0 {
		return "malicious", nil
	}
	if stats.Suspicious > 0 {
		return "suspicious", nil
	}
	return "clean", nil
}
