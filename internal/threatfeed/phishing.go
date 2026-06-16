package threatfeed

import (
	"bufio"
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// PhishingFeed fetches and caches a URL-based phishing domain list (e.g. OpenPhish).
// Implements guard.PhishingChecker.
type PhishingFeed struct {
	feedURL  string
	cacheTTL time.Duration
	db       *sql.DB
	http     *http.Client
	mu       sync.RWMutex
	domains  map[string]struct{} // in-memory set for fast lookup
	lastLoad time.Time
}

func NewPhishingFeed(feedURL string, cacheTTLHours int, db *sql.DB) *PhishingFeed {
	ttl := time.Duration(cacheTTLHours) * time.Hour
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	f := &PhishingFeed{
		feedURL:  feedURL,
		cacheTTL: ttl,
		db:       db,
		http:     &http.Client{Timeout: 15 * time.Second},
		domains:  make(map[string]struct{}),
	}
	f.loadFromDB()
	go f.refreshLoop()
	return f
}

// IsPhishing returns true if the domain appears in the phishing feed cache.
func (f *PhishingFeed) IsPhishing(domain string) bool {
	if f == nil || f.feedURL == "" {
		return false
	}
	domain = strings.ToLower(domain)
	f.mu.RLock()
	_, found := f.domains[domain]
	f.mu.RUnlock()
	return found
}

func (f *PhishingFeed) refreshLoop() {
	// Refresh immediately if cache is empty or stale, then on TTL interval.
	for {
		f.mu.RLock()
		stale := time.Since(f.lastLoad) >= f.cacheTTL
		empty := len(f.domains) == 0
		f.mu.RUnlock()

		if stale || empty {
			if err := f.fetch(); err != nil {
				log.Printf("phishing feed refresh failed: %v (using cached list)", err)
			}
		}
		time.Sleep(f.cacheTTL)
	}
}

func (f *PhishingFeed) fetch() error {
	resp, err := f.http.Get(f.feedURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	fresh := make(map[string]struct{})
	now := time.Now().Unix()

	tx, err := f.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, _ = tx.Exec(`DELETE FROM phishing_domains`)

	stmt, err := tx.Prepare(`INSERT OR REPLACE INTO phishing_domains(domain, added_at) VALUES(?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		domain := extractDomain(raw)
		if domain == "" {
			continue
		}
		fresh[domain] = struct{}{}
		stmt.Exec(domain, now)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	f.mu.Lock()
	f.domains = fresh
	f.lastLoad = time.Now()
	f.mu.Unlock()

	log.Printf("phishing feed loaded %d domains", len(fresh))
	return nil
}

func (f *PhishingFeed) loadFromDB() {
	rows, err := f.db.Query(`SELECT domain FROM phishing_domains`)
	if err != nil {
		return
	}
	defer rows.Close()
	domains := make(map[string]struct{})
	for rows.Next() {
		var d string
		if rows.Scan(&d) == nil {
			domains[d] = struct{}{}
		}
	}
	if len(domains) > 0 {
		f.mu.Lock()
		f.domains = domains
		f.mu.Unlock()
		log.Printf("phishing feed: loaded %d cached domains from DB", len(domains))
	}
}

// extractDomain parses a URL string and returns the host portion (lowercase, no port).
func extractDomain(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	// strip www. prefix so "www.evil.com" matches "evil.com"
	host = strings.TrimPrefix(host, "www.")
	return host
}
