package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/tpt-av/tpt-av/internal/alert"
	"github.com/tpt-av/tpt-av/internal/api"
	"github.com/tpt-av/tpt-av/internal/clamav"
	"github.com/tpt-av/tpt-av/internal/config"
	"github.com/tpt-av/tpt-av/internal/db"
	"github.com/tpt-av/tpt-av/internal/events"
	"github.com/tpt-av/tpt-av/internal/netmon"
	"github.com/tpt-av/tpt-av/internal/patrol"
	"github.com/tpt-av/tpt-av/internal/quarantine"
	"github.com/tpt-av/tpt-av/internal/threatfeed"
	"github.com/tpt-av/tpt-av/internal/yara"
	"github.com/tpt-av/tpt-av/web"
)

func main() {
	cfgPath := flag.String("config", "", "Path to patrol.toml")
	flag.Parse()

	cfg, err := config.LoadPatrol(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	dbPath := filepath.Join(config.DataDir(), "patrol.db")
	database, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer database.Close()

	evLog, err := events.NewLogger(cfg.EventLog.Path)
	if err != nil {
		log.Fatalf("event log: %v", err)
	}
	defer evLog.Close()

	feed, err := threatfeed.New(cfg.ThreatFeed, database)
	if err != nil {
		log.Fatalf("threatfeed: %v", err)
	}

	mailer, err := alert.New(cfg.Alerts)
	if err != nil {
		log.Fatalf("alert: %v", err)
	}

	qm, err := quarantine.New(cfg.Quarantine, database)
	if err != nil {
		log.Fatalf("quarantine: %v", err)
	}

	// YARA scanner (noop when not built with -tags yara)
	var yaraScanner patrol.FileDetector
	if cfg.YARA.Enabled && cfg.YARA.RulesDir != "" {
		ys, err := yara.NewScanner(cfg.YARA.RulesDir)
		if err != nil {
			log.Printf("yara: %v (continuing without)", err)
		} else {
			yaraScanner = ys
			defer ys.Close()
			// Auto-update rules in background
			if cfg.YARA.AutoUpdate {
				go func() {
					u := yara.NewUpdater(cfg.YARA.RulesDir, ys)
					if n, err := u.Update(); err != nil {
						log.Printf("yara update: %v", err)
					} else {
						log.Printf("yara: updated %d rule files", n)
					}
				}()
			}
		}
	}

	// ClamAV client (graceful degradation if clamd not running)
	var clamClient patrol.ClamAVScanner
	if cfg.ClamAV.Enabled && cfg.ClamAV.Socket != "" {
		c := clamav.New(cfg.ClamAV.Socket)
		if c.Ping() {
			clamClient = c
			log.Printf("clamav: connected to %s", cfg.ClamAV.Socket)
		} else {
			log.Printf("clamav: clamd not reachable at %s (continuing without)", cfg.ClamAV.Socket)
		}
	}

	// Network connection monitor
	nm := netmon.New(cfg.NetMon, evLog)
	nm.Start()
	defer nm.Stop()

	// Wrap event logger to also send alerts and auto-quarantine threats
	wrappedLog := &autoLogger{Logger: evLog, mailer: mailer, qm: qm, cfg: cfg}

	watcher, err := patrol.NewWatcher(*cfg, database, wrappedLog, feed, yaraScanner, clamClient)
	if err != nil {
		log.Fatalf("watcher: %v", err)
	}
	if err := watcher.Start(); err != nil {
		log.Fatalf("watcher start: %v", err)
	}
	defer watcher.Stop()

	scanner := patrol.NewScanner(*cfg, database, wrappedLog, feed, yaraScanner, clamClient)
	if err := scanner.Start(); err != nil {
		log.Fatalf("scanner start: %v", err)
	}
	defer scanner.Stop()

	pm := patrol.NewProcessMonitor(database, wrappedLog, feed)
	if err := pm.Start(); err != nil {
		log.Printf("process monitor: %v (continuing without)", err)
	} else {
		defer pm.Stop()
	}

	// Weekly digest cron
	var digestCron *cron.Cron
	if cfg.Alerts.WeeklyDigest {
		digestCron = cron.New()
		digestSched := cfg.Alerts.DigestCron
		if digestSched == "" {
			digestSched = "0 8 * * 0"
		}
		digest := alert.NewWeeklyDigest(cfg.Alerts, cfg.EventLog.Path)
		if _, err := digestCron.AddFunc(digestSched, func() {
			if err := digest.Send(); err != nil {
				log.Printf("weekly digest: %v", err)
			}
		}); err != nil {
			log.Printf("weekly digest cron: %v", err)
		} else {
			digestCron.Start()
			defer digestCron.Stop()
		}
	}

	// REST API
	mux := http.NewServeMux()
	registerPatrolRoutes(mux, cfg, database, evLog, scanner, qm)
	web.Register(mux) // embedded dashboard at GET /

	// Optional API auth (shares token file with guard)
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
		log.Printf("tpt-patrol API listening on %s", cfg.API.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("API error: %v", err)
		}
	}()

	evLog.Write(events.New(events.SourcePatrol, "daemon_start", events.Info, map[string]string{
		"api": cfg.API.Listen,
	}))
	log.Printf("tpt-patrol started")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	log.Printf("tpt-patrol stopped")
}

// ─── Route handlers ───────────────────────────────────────────────────────────

func registerPatrolRoutes(mux *http.ServeMux, cfg *config.PatrolConfig, database interface{ Close() error },
	evLog events.Writer, scanner *patrol.Scanner, qm *quarantine.Manager) {

	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]any{
			"status":    "running",
			"last_scan": scanner.LastScan.Format(time.RFC3339),
		})
	})

	mux.HandleFunc("GET /health-score", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, computePatrolHealthScore(cfg, evLog, scanner, qm))
	})

	mux.HandleFunc("POST /scan", func(w http.ResponseWriter, r *http.Request) {
		scanner.RunNow()
		jsonOK(w, map[string]string{"status": "scan triggered"})
	})

	mux.HandleFunc("GET /baseline", func(w http.ResponseWriter, r *http.Request) {
		stats, err := scanner.BaselineStats()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		jsonOK(w, stats)
	})

	mux.HandleFunc("POST /baseline/rebuild", func(w http.ResponseWriter, r *http.Request) {
		scanner.RebuildBaseline()
		jsonOK(w, map[string]string{"status": "baseline rebuild started"})
	})

	mux.HandleFunc("GET /quarantine", func(w http.ResponseWriter, r *http.Request) {
		list, err := qm.List()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		jsonOK(w, list)
	})

	mux.HandleFunc("POST /quarantine/{id}/restore", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := qm.Restore(id); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		jsonOK(w, map[string]string{"status": "restored"})
	})

	mux.HandleFunc("DELETE /quarantine/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := qm.Delete(id); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		jsonOK(w, map[string]string{"status": "deleted"})
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
		jsonOK(w, evts)
	})
}

func computePatrolHealthScore(cfg *config.PatrolConfig, evLog events.Writer,
	scanner *patrol.Scanner, qm *quarantine.Manager) map[string]any {

	// Count critical events in last 7 days
	criticals := 0
	since7d := time.Now().Add(-7 * 24 * time.Hour)
	if evts, err := events.ReadSince(cfg.EventLog.Path, since7d); err == nil {
		for _, e := range evts {
			if e.Severity == events.Critical {
				criticals++
			}
		}
	}

	scanRecencyOK := !scanner.LastScan.IsZero() && time.Since(scanner.LastScan) < 25*time.Hour

	factors := []map[string]any{
		{"name": "Last scan within 24h", "enabled": scanRecencyOK, "points": pointsIf(scanRecencyOK, 20), "max": 20,
			"tip": "Ensure scheduled scans are enabled and the daemon is running."},
		{"name": "Canary files", "enabled": cfg.Canary.Enabled, "points": pointsIf(cfg.Canary.Enabled, 20), "max": 20,
			"tip": "Enable [canary] enabled = true for early ransomware / intruder detection."},
		{"name": "Ransomware detection", "enabled": cfg.Ransomware.Enabled, "points": pointsIf(cfg.Ransomware.Enabled, 20), "max": 20,
			"tip": "Enable [ransomware] enabled = true to detect mass file encryption."},
		{"name": "Quarantine enabled", "enabled": cfg.Quarantine.Enabled, "points": pointsIf(cfg.Quarantine.Enabled, 20), "max": 20,
			"tip": "Enable [quarantine] to automatically isolate detected threats."},
		{"name": "No critical events (7d)", "enabled": criticals == 0, "points": pointsIf(criticals == 0, 20), "max": 20,
			"tip": fmt.Sprintf("%d critical events in the last 7 days — investigate immediately.", criticals)},
	}

	total := 0
	for _, f := range factors {
		total += f["points"].(int)
	}
	return map[string]any{"score": total, "max": 100, "factors": factors}
}

func pointsIf(cond bool, n int) int {
	if cond {
		return n
	}
	return 0
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ─── autoLogger ───────────────────────────────────────────────────────────────

type autoLogger struct {
	*events.Logger
	mailer *alert.Mailer
	qm     *quarantine.Manager
	cfg    *config.PatrolConfig
}

func (a *autoLogger) Write(e events.Event) error {
	if err := a.Logger.Write(e); err != nil {
		return err
	}
	go a.mailer.Send(e)

	if e.Type == "threat_detected" && a.cfg.Quarantine.Enabled {
		if path, ok := e.Data["path"]; ok {
			verdict := e.Data["verdict"]
			source := e.Data["source"]
			id, err := a.qm.Quarantine(path, fmt.Sprintf("verdict=%s", verdict), source)
			if err != nil {
				log.Printf("quarantine %s: %v", path, err)
			} else {
				log.Printf("quarantined %s → %s", path, id)
			}
		}
	}
	return nil
}

func init() {
	_ = os.Getenv
}
