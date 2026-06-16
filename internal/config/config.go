package config

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/BurntSushi/toml"
)

// ─── Guard ───────────────────────────────────────────────────────────────────

type GuardConfig struct {
	Network    NetworkConfig        `toml:"network"`
	Allow      AllowConfig          `toml:"allow"`
	ThreatFeed GuardThreatFeedConfig `toml:"threatfeed"`
	GeoBlock   GeoBlockConfig       `toml:"geoblock"`
	API        APIConfig            `toml:"api"`
	EventLog   EventLogConfig       `toml:"eventlog"`
}

type GeoBlockConfig struct {
	Enabled          bool     `toml:"enabled"`
	BlockedCountries []string `toml:"blocked_countries"` // ISO 3166-1 alpha-2 codes
	UpdateCron       string   `toml:"update_cron"`       // default "0 4 * * 0"
}

type GuardThreatFeedConfig struct {
	PhishingFeedURL    string `toml:"phishing_feed_url"`
	PhishingCacheTTLH  int    `toml:"phishing_cache_ttl_hours"` // default 24
	AbuseIPDBKey       string `toml:"abuseipdb_key"`
	AbuseIPDBThreshold int    `toml:"abuseipdb_threshold"` // default 75
}

type NetworkConfig struct {
	DefaultPolicy string `toml:"default_policy"` // "deny" | "allow"
	DNSListen     string `toml:"dns_listen"`     // e.g. "127.0.0.1:53"
	DNSUpstream   string `toml:"dns_upstream"`   // e.g. "8.8.8.8:53"
	DoHUpstream   string `toml:"doh_upstream"`   // e.g. "https://1.1.1.1/dns-query"
	Backend       string `toml:"backend"`        // "auto" | "iptables" | "nftables" (Linux)
}

type AllowConfig struct {
	Processes []ProcessRule `toml:"process"`
	IPs       []IPRule      `toml:"ip"`
	Domains   []DomainRule  `toml:"domain"`
}

type ProcessRule struct {
	Name    string   `toml:"name"`
	Domains []string `toml:"domains"`
	IPs     []string `toml:"ips"`
}

type IPRule struct {
	CIDR    string `toml:"cidr"`
	Comment string `toml:"comment"`
	Ports   []int  `toml:"ports"`
	Proto   string `toml:"proto"` // "tcp" | "udp" | "" (any)
}

type DomainRule struct {
	Pattern string `toml:"pattern"`
	Comment string `toml:"comment"`
}

// ─── Patrol ──────────────────────────────────────────────────────────────────

type PatrolConfig struct {
	Scan        ScanConfig        `toml:"scan"`
	Ransomware  RansomwareConfig  `toml:"ransomware"`
	Canary      CanaryConfig      `toml:"canary"`
	Quarantine  QuarantineConfig  `toml:"quarantine"`
	ThreatFeed  ThreatFeedConfig  `toml:"threatfeed"`
	YARA        YARAConfig        `toml:"yara"`
	ClamAV      ClamAVConfig      `toml:"clamav"`
	Heuristics  HeuristicsConfig  `toml:"heuristics"`
	NetMon      NetMonConfig      `toml:"netmon"`
	Alerts      AlertConfig       `toml:"alerts"`
	API         APIConfig         `toml:"api"`
	EventLog    EventLogConfig    `toml:"eventlog"`
}

type YARAConfig struct {
	Enabled    bool   `toml:"enabled"`
	RulesDir   string `toml:"rules_dir"`
	AutoUpdate bool   `toml:"auto_update"`
	UpdateCron string `toml:"update_cron"` // default "0 3 * * *"
}

type ClamAVConfig struct {
	Enabled bool   `toml:"enabled"`
	Socket  string `toml:"socket"` // Unix socket path or "host:port"
}

type HeuristicsConfig struct {
	Enabled       bool    `toml:"enabled"`
	EntropyWarn   float64 `toml:"entropy_warn"`   // default 7.2
	ScoreWarn     int     `toml:"score_warn"`     // default 70
	ScoreCritical int     `toml:"score_critical"` // default 85
}

type NetMonConfig struct {
	Enabled         bool  `toml:"enabled"`
	PollIntervalS   int   `toml:"poll_interval_s"`  // default 5
	SuspiciousPorts []int `toml:"suspicious_ports"` // default [4444,6666,6667,31337]
	BeaconThreshold int   `toml:"beacon_threshold"` // default 10
}

type RansomwareConfig struct {
	Enabled       bool `toml:"enabled"`
	Threshold     int  `toml:"threshold"`      // files changed per window before alert; default 20
	WindowSeconds int  `toml:"window_seconds"` // sliding window size; default 30
}

type CanaryConfig struct {
	Enabled bool `toml:"enabled"`
}

type ScanConfig struct {
	Schedule      string   `toml:"schedule"`       // cron expression, e.g. "0 */6 * * *"
	Window        string   `toml:"scan_window"`    // e.g. "02:00-05:00"
	Priority      string   `toml:"priority"`       // "low" | "normal"
	BatchDelayMS  int      `toml:"batch_delay_ms"` // sleep between file batches
	BaselinePaths []string `toml:"baseline_paths"`
	WatchPaths    []string `toml:"watch_paths"`
	Exclude       ExcludeConfig `toml:"exclude"`
}

type ExcludeConfig struct {
	Paths      []string `toml:"paths"`
	Extensions []string `toml:"extensions"`
}

type QuarantineConfig struct {
	Enabled bool   `toml:"enabled"`
	Path    string `toml:"path"`
	Encrypt bool   `toml:"encrypt"`
}

type ThreatFeedConfig struct {
	MalwareBazaar bool   `toml:"malwarebazaar"`
	VirusTotalKey string `toml:"virustotal_key"`
	CacheTTL      string `toml:"cache_ttl"` // e.g. "168h"
}

type AlertConfig struct {
	SMTPHost     string   `toml:"smtp_host"`
	SMTPUser     string   `toml:"smtp_user"`
	SMTPPass     string   `toml:"smtp_password"`
	Recipients   []string `toml:"recipients"`
	MinSeverity  string   `toml:"min_severity"` // "debug"|"info"|"warn"|"critical"
	Cooldown     string   `toml:"cooldown"`     // e.g. "5m"
	WeeklyDigest bool     `toml:"weekly_digest"`
	DigestCron   string   `toml:"digest_cron"` // default "0 8 * * 0"
}

// ─── Shared ───────────────────────────────────────────────────────────────────

type APIConfig struct {
	Listen      string `toml:"listen"`       // e.g. "127.0.0.1:7731"
	RequireAuth bool   `toml:"require_auth"` // default false — set true to enable Bearer token auth
}

type EventLogConfig struct {
	Path string `toml:"path"`
}

// ─── Loaders ──────────────────────────────────────────────────────────────────

func LoadGuard(path string) (*GuardConfig, error) {
	if path == "" {
		path = defaultGuardPath()
	}
	cfg := defaultGuardConfig()
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadPatrol(path string) (*PatrolConfig, error) {
	if path == "" {
		path = defaultPatrolPath()
	}
	cfg := defaultPatrolConfig()
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func defaultGuardPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "TPT", "guard.toml")
	}
	return "/etc/tpt/guard.toml"
}

func defaultPatrolPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "TPT", "patrol.toml")
	}
	return "/etc/tpt/patrol.toml"
}

func DataDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "TPT", "data")
	}
	return "/var/lib/tpt"
}

func LogDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "TPT", "logs")
	}
	return "/var/log/tpt"
}

func defaultGuardConfig() *GuardConfig {
	return &GuardConfig{
		Network: NetworkConfig{
			DefaultPolicy: "deny",
			DNSListen:     "127.0.0.1:5353",
			DNSUpstream:   "8.8.8.8:53",
		},
		ThreatFeed: GuardThreatFeedConfig{
			PhishingFeedURL:   "https://openphish.com/feed.txt",
			PhishingCacheTTLH: 24,
			AbuseIPDBThreshold: 75,
		},
		API:      APIConfig{Listen: "127.0.0.1:7731"},
		EventLog: EventLogConfig{Path: filepath.Join(LogDir(), "events.jsonl")},
	}
}

func defaultPatrolConfig() *PatrolConfig {
	return &PatrolConfig{
		Scan: ScanConfig{
			Schedule:     "0 */6 * * *",
			Priority:     "low",
			BatchDelayMS: 10,
			Exclude: ExcludeConfig{
				Paths:      []string{"/proc", "/sys", "/dev", "/run"},
				Extensions: []string{".log", ".tmp", ".swp"},
			},
		},
		Ransomware: RansomwareConfig{
			Enabled:       true,
			Threshold:     20,
			WindowSeconds: 30,
		},
		Canary: CanaryConfig{
			Enabled: true,
		},
		Quarantine: QuarantineConfig{
			Enabled: true,
			Path:    filepath.Join(DataDir(), "quarantine"),
			Encrypt: true,
		},
		ThreatFeed: ThreatFeedConfig{
			MalwareBazaar: true,
			CacheTTL:      "168h",
		},
		YARA: YARAConfig{
			Enabled:    false,
			AutoUpdate: true,
			UpdateCron: "0 3 * * *",
		},
		ClamAV: ClamAVConfig{
			Enabled: false,
			Socket:  "/var/run/clamav/clamd.ctl",
		},
		Heuristics: HeuristicsConfig{
			Enabled:       true,
			EntropyWarn:   7.2,
			ScoreWarn:     70,
			ScoreCritical: 85,
		},
		NetMon: NetMonConfig{
			Enabled:         true,
			PollIntervalS:   5,
			SuspiciousPorts: []int{4444, 6666, 6667, 31337, 1337, 8888, 9999},
			BeaconThreshold: 10,
		},
		Alerts: AlertConfig{
			MinSeverity:  "warn",
			Cooldown:     "5m",
			WeeklyDigest: true,
			DigestCron:   "0 8 * * 0",
		},
		API:      APIConfig{Listen: "127.0.0.1:7732"},
		EventLog: EventLogConfig{Path: filepath.Join(LogDir(), "events.jsonl")},
	}
}

// ─── Backup config ────────────────────────────────────────────────────────────

type BackupConfig struct {
	SourcePaths []string          `toml:"source_paths"`
	Schedule    string            `toml:"schedule"` // cron expression
	Local       LocalBackupConfig `toml:"local"`
	Cloud       CloudBackupConfig `toml:"cloud"`
	EventLog    EventLogConfig    `toml:"eventlog"`
}

type LocalBackupConfig struct {
	Enabled bool   `toml:"enabled"`
	Dest    string `toml:"dest"`
	Retain  int    `toml:"retain"` // number of snapshots to keep; default 7
}

type CloudBackupConfig struct {
	Enabled    bool   `toml:"enabled"`
	Endpoint   string `toml:"endpoint"`    // "s3.wasabisys.com"
	Bucket     string `toml:"bucket"`
	AccessKey  string `toml:"access_key"`
	SecretKey  string `toml:"secret_key"`
	Region     string `toml:"region"`     // default "us-east-1"
	Passphrase string `toml:"passphrase"` // AES-256 encryption key (empty = no encryption)
}

func LoadBackup(path string) (*BackupConfig, error) {
	if path == "" {
		path = defaultBackupPath()
	}
	cfg := defaultBackupConfig()
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func defaultBackupPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "TPT", "backup.toml")
	}
	return "/etc/tpt/backup.toml"
}

func defaultBackupConfig() *BackupConfig {
	return &BackupConfig{
		Schedule: "0 2 * * *", // daily at 02:00
		Local: LocalBackupConfig{
			Enabled: false,
			Retain:  7,
		},
		Cloud: CloudBackupConfig{
			Enabled:  false,
			Endpoint: "s3.wasabisys.com",
			Region:   "us-east-1",
		},
		EventLog: EventLogConfig{Path: filepath.Join(LogDir(), "events.jsonl")},
	}
}
