package threatfeed

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// AbuseChecker queries AbuseIPDB for IP reputation.
// Implements guard.IPReputationChecker.
type AbuseChecker struct {
	apiKey     string
	threshold  int // 0-100; IPs with abuseConfidenceScore >= threshold are blocked
	db         *sql.DB
	http       *http.Client
	mu         sync.RWMutex
	inProgress map[string]bool // deduplicate concurrent lookups
}

func NewAbuseChecker(apiKey string, threshold int, db *sql.DB) *AbuseChecker {
	if threshold <= 0 {
		threshold = 75
	}
	return &AbuseChecker{
		apiKey:     apiKey,
		threshold:  threshold,
		db:         db,
		http:       &http.Client{Timeout: 8 * time.Second},
		inProgress: make(map[string]bool),
	}
}

// IsAbusive returns true if the IP's AbuseIPDB confidence score meets the threshold.
// Unknown or unreachable: returns false (fail-open to avoid false positives).
func (a *AbuseChecker) IsAbusive(ip string) bool {
	if a == nil || a.apiKey == "" {
		return false
	}

	// Check threat_cache table first (shared with MalwareBazaar/VT).
	// Source prefix "abuseipdb:" distinguishes these entries.
	cacheKey := "ip:" + ip
	if verdict, _, ok := a.fromCache(cacheKey); ok {
		return verdict == "abusive"
	}

	// Async lookup — don't block DNS resolution; return false now.
	a.mu.Lock()
	if a.inProgress[ip] {
		a.mu.Unlock()
		return false
	}
	a.inProgress[ip] = true
	a.mu.Unlock()

	go func() {
		defer func() {
			a.mu.Lock()
			delete(a.inProgress, ip)
			a.mu.Unlock()
		}()
		score, err := a.queryAPI(ip)
		if err != nil {
			log.Printf("abuseipdb query %s: %v", ip, err)
			return
		}
		verdict := "clean"
		if score >= a.threshold {
			verdict = "abusive"
			log.Printf("abuseipdb: blocked %s (score=%d)", ip, score)
		}
		a.cacheResult(cacheKey, verdict, "abuseipdb")
	}()

	return false // result available on next DNS query for same domain
}

type abuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int `json:"abuseConfidenceScore"`
	} `json:"data"`
}

func (a *AbuseChecker) queryAPI(ip string) (int, error) {
	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=30", ip), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Key", a.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := a.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}
	return result.Data.AbuseConfidenceScore, nil
}

func (a *AbuseChecker) fromCache(key string) (verdict, source string, ok bool) {
	row := a.db.QueryRow(
		`SELECT verdict, source, checked_at FROM threat_cache WHERE hash=?`, key)
	var checkedAt int64
	if err := row.Scan(&verdict, &source, &checkedAt); err != nil {
		return "", "", false
	}
	// Cache AbuseIPDB results for 24h (IPs change faster than file hashes)
	if time.Since(time.Unix(checkedAt, 0)) > 24*time.Hour {
		return "", "", false
	}
	return verdict, source, true
}

func (a *AbuseChecker) cacheResult(key, verdict, source string) {
	a.db.Exec(`
		INSERT INTO threat_cache(hash, verdict, source, checked_at)
		VALUES(?,?,?,?)
		ON CONFLICT(hash) DO UPDATE SET
			verdict=excluded.verdict, source=excluded.source, checked_at=excluded.checked_at`,
		key, verdict, source, time.Now().Unix())
}
