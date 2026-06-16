package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/tpt-av/tpt-av/internal/backup"
	"github.com/tpt-av/tpt-av/internal/config"
	dbpkg "github.com/tpt-av/tpt-av/internal/db"
	"github.com/tpt-av/tpt-av/internal/events"
)

func main() {
	cfgPath := flag.String("config", "", "Path to backup.toml")
	runNow := flag.Bool("run", false, "Run backup immediately then exit")
	flag.Parse()

	cfg, err := config.LoadBackup(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	dbPath := filepath.Join(config.DataDir(), "backup.db")
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

	sched := backup.NewScheduler(*cfg, database, evLog)

	if *runNow {
		sched.RunNow()
		// Wait briefly for async goroutine
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-sig:
		}
		return
	}

	if err := sched.Start(); err != nil {
		log.Fatalf("backup scheduler: %v", err)
	}
	defer sched.Stop()

	evLog.Write(events.New(events.SourcePatrol, "daemon_start", events.Info,
		map[string]string{"daemon": "tpt-backup", "schedule": cfg.Schedule}))
	log.Printf("tpt-backup started (schedule=%s)", cfg.Schedule)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("tpt-backup stopped")
}
