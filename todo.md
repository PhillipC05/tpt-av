# tpt-av TODO

> Status updated 2026-06-16. Core implementation is complete across Guard, Patrol,
> Backup, the CLI, the web dashboard, and the system tray. Remaining work is mostly
> real-world platform testing/verification and a few optional hardening items.

## Project Setup
- [x] Init Go module (`go.mod` / `go.sum` present)
- [x] Create directory structure (`cmd/`, `internal/`, `web/`, `config/`, `systemd/`, `windows/`, `nsis/`)
- [x] Add `.gitignore`, `LICENSE`, `README` (plus `CHANGELOG`, `CONTRIBUTING`, `SECURITY`, `NOTICE`)

## Shared / Internal
- [x] `internal/config` — TOML config loader (shared structs for Guard + Patrol + Backup)
- [x] `internal/events` — JSONL event log writer + reader (append-only, shared between daemons)
- [x] `internal/db` — SQLite helper (open/migrate, baseline table, threat cache table, quarantine table)
- [x] `internal/api` — shared REST helpers + token auth (`internal/api/auth.go`)

## TPT Guard
- [x] Guard config struct + TOML parsing
- [x] Linux: nftables rule manager (`firewall_nft_linux.go`, `firewall_linux.go`)
- [x] Linux: DNS stub resolver with domain whitelist (`dns.go`, `dns_linux.go`)
- [x] Windows: WFP user-mode integration (`wfp_windows.go`, `firewall_windows.go`, `dns_windows.go`)
- [x] Guard REST API (localhost:7731) — status, rules CRUD, events tail
- [x] Guard event log integration (`connection_blocked`, `connection_allowed`, `rule_added`, `rule_removed`)
- [x] Guard systemd unit file (`systemd/tpt-guard.service`)
- [x] Guard Windows Service wrapper (`windows/service.go`)
- [x] DNS-over-HTTPS resolver (`doh.go`)
- [x] GeoIP / country-based blocking (`geoblock.go`)

## TPT Patrol
- [x] Patrol config struct + TOML parsing
- [x] Baseline builder — walk dirs, SHA-256 each file, store in SQLite (`baseline.go`)
- [x] Folder quick pre-check — compare file count + total bytes before hashing
- [x] Exclusion list filtering — skip configured paths and file extensions
- [x] Real-time watcher — `fsnotify` with debounce (`watcher.go`)
- [x] Scheduled scan loop — cron + `scan_window` time-of-day restriction (`scanner.go`)
- [x] Below-normal OS priority for scan goroutines (`priority_linux.go`, `priority_windows.go`)
- [x] Per-batch I/O delay — configurable `batch_delay_ms`
- [x] Process creation monitor (`procmon_linux.go`, `procmon_windows.go`)
- [x] Process baseline — hash running executables, flag new/changed exe
- [x] Quarantine system — move + UUID-rename, metadata to SQLite (`internal/quarantine`)
- [x] Quarantine AES-256 encryption (optional, configurable)
- [x] Quarantine CLI: `list`, `restore <id>`, `delete <id>`
- [x] Threat feed: MalwareBazaar client (free hash lookup, no API key)
- [x] Threat feed: VirusTotal client (optional API key)
- [x] Threat feed local cache in SQLite with TTL
- [x] Email alert system — SMTP, per-type cooldown, severity threshold (`internal/alert/smtp.go`)
- [x] Daily/periodic digest alerts (`internal/alert/digest.go`)
- [x] Patrol REST API (localhost:7732) — status, scan, baseline, quarantine, events
- [x] Patrol event log integration (all event types)
- [x] Patrol systemd unit file (`systemd/tpt-patrol.service`)
- [x] Patrol Windows Service wrapper
- [x] ClamAV integration (`internal/clamav/client.go`)
- [x] YARA scanning + rule updater (`internal/yara`, with `noop.go` fallback when CGO/yara absent)
- [x] Static heuristics — PE/ELF parsing + entropy analysis (`internal/heuristics`)
- [x] Ransomware behavior detection (`internal/patrol/ransomware.go`)
- [x] Canary / honeypot files (`internal/patrol/canary.go`)
- [x] AbuseIPDB IP reputation feed (`internal/threatfeed/abuseipdb.go`)
- [x] Phishing URL feed (`internal/threatfeed/phishing.go`)

## TPT Backup (new component)
- [x] Backup config struct + TOML parsing (`config/backup.toml.example`)
- [x] Local backup target (`internal/backup/local.go`)
- [x] S3-compatible backup target (`internal/backup/s3.go`)
- [x] Backup scheduler (`internal/backup/scheduler.go`)
- [x] Backup daemon (`cmd/tpt-backup`)
- [x] Backup systemd unit file (`systemd/tpt-backup.service`)

## Network Monitor
- [x] Connection/netmon tracking (`internal/netmon/monitor_linux.go`, `monitor_windows.go`)

## CLI (tptctl)
- [x] Cobra CLI skeleton + root command
- [x] `guard status` — daemon state, rule count
- [x] `guard rules list` — current rules
- [x] `guard rules allow ...` — add allow rule
- [x] `guard rules deny ...` — add explicit deny rule
- [x] `patrol status` — watcher state, last scan, quarantine count
- [x] `patrol scan [--path]` — trigger immediate scan
- [x] `patrol quarantine list / restore <id> / delete <id>`
- [x] `events [--tail] [--source]` — stream shared event log
- [x] `patrol baseline [--rebuild]` — shows baseline summary or rebuilds (Patrol `GET /baseline`, `POST /baseline/rebuild`)

## System Tray (new component)
- [x] Cross-platform tray app (`cmd/tpt-tray`) with status + dashboard launcher

## Web Dashboard
- [x] Single-page HTML + vanilla JS (`web/static/index.html`)
- [x] Guard panel: rules table, add/remove controls
- [x] Patrol panel: events feed, last scan, quarantine count
- [x] Auto-refresh via fetch
- [x] Warn in UI if dashboard bound to `0.0.0.0` instead of localhost
- [x] Embed static files via `embed.FS` (`web/web.go`)
- [x] Serve dashboard from Guard (`:7731`) and Patrol (`:7732`) at `GET /`, with loopback-only CORS for cross-port calls (`internal/api` `LoopbackCORS`)

## Cross-platform & Build / Packaging
- [x] `Makefile` — `build-linux`, `build-linux-arm64`, `build-windows`, `build-all`
- [x] Cross-compile targets: `linux/amd64`, `linux/arm64`, `windows/amd64`
- [x] Windows installer (`nsis/installer.nsi`, `make installer-windows`)
- [x] Install scripts (`install.sh`, `install.ps1`)
- [x] Docker support (`Dockerfile`, `docker-compose.yml`, `.dockerignore`)
- [x] Release automation (`.goreleaser.yml`)
- [ ] Test on Linux (Ubuntu/Debian)
- [ ] Test on Windows 11
- [ ] Test on headless VPS (Linux, no GUI)
- [ ] CGO/YARA build verification (`go build -tags yara`) on a target with libyara

## Documentation
- [x] `README.md` — installation, config, quick-start usage
- [x] `config/guard.toml.example` — annotated example Guard config
- [x] `config/patrol.toml.example` — annotated example Patrol config
- [x] `config/backup.toml.example` — annotated example Backup config
- [ ] Systemd setup instructions (verify covered in README)
- [ ] Windows Service setup instructions (verify covered in README)

---

## Event Types Reference

| Source  | Type               | Severity |
|---------|--------------------|----------|
| patrol  | file_changed       | warn     |
| patrol  | new_file           | info     |
| patrol  | file_deleted       | warn     |
| patrol  | threat_detected    | critical |
| patrol  | process_created    | info     |
| patrol  | process_anomaly    | warn     |
| patrol  | scan_complete      | info     |
| guard   | connection_blocked | info     |
| guard   | connection_allowed | debug    |
| guard   | rule_added         | info     |
| guard   | rule_removed       | info     |

## Verification Checklist (real-world, still to run)
- [ ] Rebuild baseline → modify watched file → event appears in `tptctl events --tail`
- [ ] Rebuild baseline → scan with no changes → verify instant skip (no hashes computed)
- [ ] Submit known-bad hash → `threat_detected` event + file moved to quarantine
- [ ] `tptctl patrol quarantine list` shows entry; `restore` moves file back
- [ ] Trigger threat → email received at configured address
- [ ] Start new process not in baseline → `process_created` event logged
- [ ] Outbound connection from non-whitelisted process → `connection_blocked` event
- [ ] Add process to whitelist → connection succeeds
- [ ] Run scan with `batch_delay_ms = 50` on large dir → CPU stays low
- [ ] `make build-linux` + `make build-windows` → both binaries produced
- [ ] Deploy to Ubuntu VPS → systemd service starts, events log populates
- [ ] Backup: run scheduled backup to local + S3 target → verify artifacts
- [ ] Canary file modified → ransomware/canary alert fires
