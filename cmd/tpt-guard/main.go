package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tpt-av/tpt-av/internal/api"
	"github.com/tpt-av/tpt-av/internal/config"
	dbpkg "github.com/tpt-av/tpt-av/internal/db"
	"github.com/tpt-av/tpt-av/internal/events"
	"github.com/tpt-av/tpt-av/internal/guard"
	"github.com/tpt-av/tpt-av/internal/threatfeed"
	"github.com/tpt-av/tpt-av/web"
)

func main() {
	cfgPath := flag.String("config", "", "Path to guard.toml")
	flag.Parse()

	cfg, err := config.LoadGuard(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	dbPath := filepath.Join(config.DataDir(), "guard.db")
	database, err := dbpkg.Open(dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer database.Close()

	evLog, err := events.NewLogger(cfg.EventLog.Path)
	if err != nil {
		log.Fatalf("event log: %v", err)
	}
	defer evLog.Close()

	fw := guard.NewFirewall(*cfg, database, evLog)
	if err := fw.Apply(); err != nil {
		log.Printf("firewall: %v (continuing)", err)
	}
	defer fw.Flush()

	// Geo-blocking (downloads country IP ranges and adds DROP rules)
	gb := guard.NewGeoBlocker(cfg.GeoBlock, fw, database, evLog)
	gb.Start()
	defer gb.Stop()

	// Optional threat feeds for the DNS resolver
	var phishing guard.PhishingChecker
	if cfg.ThreatFeed.PhishingFeedURL != "" {
		phishing = threatfeed.NewPhishingFeed(
			cfg.ThreatFeed.PhishingFeedURL,
			cfg.ThreatFeed.PhishingCacheTTLH,
			database,
		)
	}

	var abuseIP guard.IPReputationChecker
	if cfg.ThreatFeed.AbuseIPDBKey != "" {
		abuseIP = threatfeed.NewAbuseChecker(
			cfg.ThreatFeed.AbuseIPDBKey,
			cfg.ThreatFeed.AbuseIPDBThreshold,
			database,
		)
	}

	resolver := guard.NewDNSResolver(*cfg, evLog, phishing, abuseIP)
	if err := resolver.Start(); err != nil {
		log.Printf("dns resolver: %v (continuing without)", err)
	} else {
		defer resolver.Stop()
	}

	mux := http.NewServeMux()
	registerGuardRoutes(mux, cfg, database, evLog, fw)
	web.Register(mux) // embedded dashboard at GET /

	// Optional API auth
	var token string
	if cfg.API.RequireAuth {
		token, err = api.EnsureToken()
		if err != nil {
			log.Fatalf("api token: %v", err)
		}
	}
	handler := api.WrapMux(mux, cfg.API.RequireAuth, token)

	srv := &http.Server{Addr: cfg.API.Listen, Handler: handler}
	go func() {
		log.Printf("tpt-guard API listening on %s", cfg.API.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("API error: %v", err)
		}
	}()

	evLog.Write(events.New(events.SourceGuard, "daemon_start", events.Info,
		map[string]string{"api": cfg.API.Listen, "policy": cfg.Network.DefaultPolicy}))
	log.Printf("tpt-guard started (policy=%s)", cfg.Network.DefaultPolicy)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	log.Printf("tpt-guard stopped")
}

type Rule struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`
	Process   string `json:"process,omitempty"`
	Domain    string `json:"domain,omitempty"`
	IPCIDR    string `json:"ip_cidr,omitempty"`
	Comment   string `json:"comment,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

func registerGuardRoutes(mux *http.ServeMux, cfg *config.GuardConfig,
	database *sql.DB, evLog *events.Logger, fw *guard.Firewall) {

	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]string{
			"status": "running",
			"policy": cfg.Network.DefaultPolicy,
		})
	})

	mux.HandleFunc("GET /health-score", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, computeGuardHealthScore(cfg, database, evLog))
	})

	mux.HandleFunc("GET /rules", func(w http.ResponseWriter, r *http.Request) {
		rows, err := database.Query(
			`SELECT id, type, COALESCE(process,''), COALESCE(domain,''), COALESCE(ip_cidr,''), COALESCE(comment,''), created_at
			 FROM guard_rules ORDER BY id`)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()
		var rules []Rule
		for rows.Next() {
			var ru Rule
			if err := rows.Scan(&ru.ID, &ru.Type, &ru.Process, &ru.Domain, &ru.IPCIDR, &ru.Comment, &ru.CreatedAt); err != nil {
				continue
			}
			rules = append(rules, ru)
		}
		jsonOK(w, rules)
	})

	mux.HandleFunc("POST /rules/allow/ip", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CIDR    string `json:"cidr"`
			Comment string `json:"comment"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := fw.AddAllow(body.CIDR, body.Comment); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		jsonOK(w, map[string]string{"status": "added"})
	})

	mux.HandleFunc("DELETE /rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		row := database.QueryRow(`SELECT ip_cidr FROM guard_rules WHERE id=?`, id)
		var cidr string
		if err := row.Scan(&cidr); err != nil {
			http.Error(w, "rule not found", 404)
			return
		}
		if err := fw.RemoveAllow(cidr); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		jsonOK(w, map[string]string{"status": "removed"})
	})

	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		sinceStr := r.URL.Query().Get("since")
		var since time.Time
		if sinceStr != "" {
			since, _ = time.Parse(time.RFC3339, sinceStr)
		}
		evts, err := events.ReadSince(cfg.EventLog.Path, since)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		var filtered []events.Event
		for _, e := range evts {
			if e.Source == events.SourceGuard {
				filtered = append(filtered, e)
			}
		}
		jsonOK(w, filtered)
	})
}

type healthFactor struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Points  int    `json:"points"`
	Max     int    `json:"max"`
	Tip     string `json:"tip,omitempty"`
}

type healthScore struct {
	Score   int            `json:"score"`
	Max     int            `json:"max"`
	Factors []healthFactor `json:"factors"`
}

func computeGuardHealthScore(cfg *config.GuardConfig, db *sql.DB, evLog *events.Logger) healthScore {
	factors := []healthFactor{
		{
			Name:    "Default-deny policy",
			Enabled: cfg.Network.DefaultPolicy == "deny",
			Points:  25, Max: 25,
			Tip: "Set [network] default_policy = \"deny\" to block all unknown outbound traffic.",
		},
		{
			Name:    "DNS-over-HTTPS",
			Enabled: cfg.Network.DoHUpstream != "",
			Points:  20, Max: 20,
			Tip: "Set [network] doh_upstream to prevent DNS hijacking on untrusted networks.",
		},
		{
			Name:    "Phishing feed",
			Enabled: cfg.ThreatFeed.PhishingFeedURL != "",
			Points:  20, Max: 20,
			Tip: "Enable [threatfeed] phishing_feed_url to block known phishing domains.",
		},
		{
			Name:    "AbuseIPDB",
			Enabled: cfg.ThreatFeed.AbuseIPDBKey != "",
			Points:  20, Max: 20,
			Tip: "Add an AbuseIPDB API key to [threatfeed] to block malicious IPs.",
		},
		{
			Name:    "API authentication",
			Enabled: cfg.API.RequireAuth,
			Points:  15, Max: 15,
			Tip: "Set [api] require_auth = true to protect the Guard API with a Bearer token.",
		},
	}

	total, max := 0, 0
	for i, f := range factors {
		max += f.Max
		if f.Enabled {
			total += f.Points
		} else {
			factors[i].Points = 0
		}
	}

	return healthScore{Score: total, Max: max, Factors: factors}
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
