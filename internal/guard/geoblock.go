package guard

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/tpt-av/tpt-av/internal/config"
	"github.com/tpt-av/tpt-av/internal/events"
)

// GeoBlocker downloads per-country CIDR lists from ipverse/rir-ip and applies
// DROP rules via the Firewall. It is self-contained: if the feed is unreachable,
// previously cached rules remain in the DB and are re-applied on startup.
type GeoBlocker struct {
	cfg      config.GeoBlockConfig
	fw       *Firewall
	db       *sql.DB
	log      *events.Logger
	http     *http.Client
	mu       sync.Mutex
	cron     *cron.Cron
}

// ipverseURL returns the raw URL for a country's aggregated IPv4 CIDR list.
func ipverseURL(cc string) string {
	return fmt.Sprintf(
		"https://raw.githubusercontent.com/ipverse/rir-ip/master/country/%s/ipv4-aggregated.txt",
		strings.ToLower(cc),
	)
}

func NewGeoBlocker(cfg config.GeoBlockConfig, fw *Firewall, db *sql.DB, log *events.Logger) *GeoBlocker {
	return &GeoBlocker{
		cfg:  cfg,
		fw:   fw,
		db:   db,
		log:  log,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// Start loads cached rules from SQLite, applies them to the firewall, then
// schedules weekly refresh.
func (g *GeoBlocker) Start() {
	if !g.cfg.Enabled || len(g.cfg.BlockedCountries) == 0 {
		return
	}

	// Apply cached blocks from previous run immediately
	g.applyCached()

	// Schedule refresh
	sched := g.cfg.UpdateCron
	if sched == "" {
		sched = "0 4 * * 0" // Sunday 04:00
	}
	g.cron = cron.New()
	g.cron.AddFunc(sched, g.refresh)
	g.cron.Start()

	// Also refresh now in background if cache is stale (>7 days old)
	go g.refreshIfStale()
}

func (g *GeoBlocker) Stop() {
	if g.cron != nil {
		g.cron.Stop()
	}
}

func (g *GeoBlocker) applyCached() {
	rows, err := g.db.Query(`SELECT ip_cidr, comment FROM guard_rules WHERE type='geo_block'`)
	if err != nil {
		return
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var cidr, comment string
		if rows.Scan(&cidr, &comment) == nil {
			g.fw.BlockCIDR(cidr, comment)
			count++
		}
	}
	if count > 0 {
		g.log.Write(events.New(events.SourceGuard, "geoblock_applied", events.Info,
			map[string]string{"cached_cidrs": fmt.Sprintf("%d", count)}))
	}
}

func (g *GeoBlocker) refreshIfStale() {
	var lastUpdated int64
	g.db.QueryRow(`SELECT MAX(created_at) FROM guard_rules WHERE type='geo_block'`).Scan(&lastUpdated)
	if time.Since(time.Unix(lastUpdated, 0)) > 7*24*time.Hour {
		g.refresh()
	}
}

func (g *GeoBlocker) refresh() {
	g.mu.Lock()
	defer g.mu.Unlock()

	total := 0
	for _, cc := range g.cfg.BlockedCountries {
		n, err := g.fetchAndBlock(cc)
		if err != nil {
			g.log.Write(events.New(events.SourceGuard, "geoblock_fetch_error", events.Warn,
				map[string]string{"country": cc, "error": err.Error()}))
			continue
		}
		total += n
	}

	g.log.Write(events.New(events.SourceGuard, "geoblock_refreshed", events.Info,
		map[string]string{"total_cidrs": fmt.Sprintf("%d", total)}))
}

func (g *GeoBlocker) fetchAndBlock(cc string) (int, error) {
	resp, err := g.http.Get(ipverseURL(cc))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d for country %s", resp.StatusCode, cc)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MB max
	if err != nil {
		return 0, err
	}

	// Clear old entries for this country before inserting new ones
	g.db.Exec(`DELETE FROM guard_rules WHERE type='geo_block' AND comment=?`, "geo:"+cc)
	g.fw.FlushGeoBlocks()

	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	now := time.Now().Unix()
	tx, _ := g.db.Begin()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := g.fw.BlockCIDR(line, "geo:"+cc); err == nil {
			if tx != nil {
				tx.Exec(
					`INSERT OR REPLACE INTO guard_rules(type,ip_cidr,comment,created_at) VALUES(?,?,?,?)`,
					"geo_block", line, "geo:"+cc, now)
			}
			count++
		}
	}
	if tx != nil {
		tx.Commit()
	}
	return count, nil
}
