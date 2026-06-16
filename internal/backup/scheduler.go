package backup

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/tpt-av/tpt-av/internal/config"
	"github.com/tpt-av/tpt-av/internal/events"
)

// Scheduler runs local and cloud backups on a cron schedule.
type Scheduler struct {
	cfg    config.BackupConfig
	db     *sql.DB
	log    *events.Logger
	local  *LocalBackup
	cloud  *S3Client
	cron   *cron.Cron
}

func NewScheduler(cfg config.BackupConfig, db *sql.DB, log *events.Logger) *Scheduler {
	var local *LocalBackup
	if cfg.Local.Enabled {
		local = NewLocalBackup(cfg.Local.Dest, cfg.Local.Retain)
	}

	var cloud *S3Client
	if cfg.Cloud.Enabled {
		cloud = NewS3Client(
			cfg.Cloud.Endpoint,
			cfg.Cloud.Bucket,
			cfg.Cloud.AccessKey,
			cfg.Cloud.SecretKey,
			cfg.Cloud.Region,
			cfg.Cloud.Passphrase,
			db,
		)
	}

	return &Scheduler{
		cfg:   cfg,
		db:    db,
		log:   log,
		local: local,
		cloud: cloud,
		cron:  cron.New(),
	}
}

// Start registers the cron job and begins the scheduler.
func (s *Scheduler) Start() error {
	sched := s.cfg.Schedule
	if sched == "" {
		sched = "0 2 * * *"
	}
	_, err := s.cron.AddFunc(sched, s.run)
	if err != nil {
		return fmt.Errorf("invalid backup schedule %q: %w", sched, err)
	}
	s.cron.Start()
	log.Printf("tpt-backup scheduled: %s", sched)
	return nil
}

// Stop halts the scheduler.
func (s *Scheduler) Stop() {
	s.cron.Stop()
}

// RunNow triggers an immediate backup (used by tptctl backup run).
func (s *Scheduler) RunNow() {
	go s.run()
}

func (s *Scheduler) run() {
	start := time.Now()
	log.Printf("tpt-backup: starting backup run")

	var errs []string

	if s.local != nil {
		if err := s.local.Run(s.cfg.SourcePaths); err != nil {
			errs = append(errs, "local: "+err.Error())
		} else {
			log.Printf("tpt-backup: local backup complete")
		}
	}

	if s.cloud != nil {
		if err := s.cloud.UploadChanged(s.cfg.SourcePaths); err != nil {
			errs = append(errs, "cloud: "+err.Error())
		} else {
			log.Printf("tpt-backup: cloud backup complete")
		}
	}

	elapsed := time.Since(start).Round(time.Second)
	data := map[string]string{"elapsed": elapsed.String()}
	if len(errs) > 0 {
		data["errors"] = fmt.Sprintf("%v", errs)
		s.log.Write(events.New(events.SourcePatrol, "backup_failed", events.Warn, data))
	} else {
		s.log.Write(events.New(events.SourcePatrol, "backup_complete", events.Info, data))
	}
}
