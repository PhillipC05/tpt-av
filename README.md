# TPT-AV

> Lightweight, open-source endpoint security suite for Linux and Windows.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.25%2B-00ADD8.svg)](go.mod)
[![Release](https://img.shields.io/github/v/release/tpt-av/tpt-av?include_prereleases)](https://github.com/tpt-av/tpt-av/releases)

TPT-AV is a suite of small, focused daemons that protect endpoints against
network intrusion, malware, file tampering, phishing, and ransomware — without
the bloat of a traditional antivirus. It runs on a single host, stores data
locally, and exposes everything over a localhost REST API, a CLI, and an
optional web dashboard.

> ⚠️ **Status:** Early-stage software. Review the configuration and test in a
> non-production environment before relying on it. See [SECURITY.md](SECURITY.md)
> for how to report vulnerabilities.

---

## Components

| Binary        | Role                                                                                  |
|---------------|---------------------------------------------------------------------------------------|
| `tpt-guard`   | Outbound firewall (nftables/iptables on Linux, netsh on Windows) + DNS stub resolver with default-deny whitelisting and DNS-over-HTTPS. |
| `tpt-patrol`  | File-integrity baseline + real-time watcher, process monitor, quarantine, and threat-feed lookups (ClamAV, YARA, heuristics). |
| `tpt-backup`  | Local + Wasabi (S3-compatible) cloud backup daemon with AES-256 encryption.           |
| `tptctl`      | Command-line control tool for Guard, Patrol, and the shared event log.                 |
| `tpt-tray`    | Windows system-tray status icon (Windows only).                                        |

### Highlights

- **Default-deny outbound firewall** — only whitelisted processes/domains reach the network.
- **Ransomware detection** — mass file-change heuristics with canary/honeypot files.
- **File-integrity monitoring** — SHA-256 baseline with a low-priority, throttled scanner.
- **Threat intelligence** — MalwareBazaar, VirusTotal, AbuseIPDB, and OpenPhish feeds.
- **Quarantine** — isolate, encrypt, list, and restore suspicious files.
- **Alerting** — SMTP email alerts with per-type cooldowns and a weekly security digest.
- **Local-first** — all data stored in SQLite; the API binds to `127.0.0.1` by default.

---

## Installation

### Pre-built binaries

Download the archive for your platform from the
[Releases](https://github.com/tpt-av/tpt-av/releases) page and extract it.

### Linux (install script)

```sh
curl -fsSL https://raw.githubusercontent.com/tpt-av/tpt-av/main/install.sh | sudo sh
```

Or with the Makefile from source:

```sh
git clone https://github.com/tpt-av/tpt-av.git
cd tpt-av
sudo make install-linux
sudo systemctl enable --now tpt-guard tpt-patrol
```

### Windows (PowerShell, run as Administrator)

```powershell
irm https://raw.githubusercontent.com/tpt-av/tpt-av/main/install.ps1 | iex
```

Or run the NSIS installer from the release archive.

### Docker (Linux host)

```sh
docker compose up -d
```

> Full firewall and process-monitor functionality requires host-level
> privileges; some features are limited inside containers.

For production rollouts — systemd/Windows service management, required
privileges, hardening, upgrades, and uninstall — see
[**DEPLOYMENT.md**](DEPLOYMENT.md).

---

## Build from source

Requires **Go 1.25+**. SQLite is provided by the pure-Go `modernc.org/sqlite`,
so most builds need no CGo; the Windows tray (`tpt-tray`) and the optional YARA
build do require a CGo toolchain.

```sh
make build-linux        # linux/amd64 → bin/linux/
make build-linux-arm64  # linux/arm64
make build-windows      # windows/amd64 → bin/windows/
make build-all          # all of the above
make build-yara         # YARA-enabled patrol (needs libyara-dev, -tags yara)
```

---

## Configuration

Annotated example configs live in [`config/`](config/):

- [`config/guard.toml.example`](config/guard.toml.example)
- [`config/patrol.toml.example`](config/patrol.toml.example)
- [`config/backup.toml.example`](config/backup.toml.example)

Copy them to the platform config directory and edit:

| Platform | Config directory                |
|----------|---------------------------------|
| Linux    | `/etc/tpt/`                     |
| Windows  | `C:\ProgramData\TPT\`           |

When API authentication is enabled, the bearer token is read from
`/etc/tpt/api.token` (Linux) or `C:\ProgramData\TPT\api.token` (Windows).

### API ports

| Daemon       | Address              |
|--------------|----------------------|
| `tpt-guard`  | `127.0.0.1:7731`     |
| `tpt-patrol` | `127.0.0.1:7732`     |

---

## Usage

```sh
# Guard
tptctl guard status
tptctl guard rules list
tptctl guard rules allow --process curl --domain '*.example.com'

# Patrol
tptctl patrol status
tptctl patrol scan --path /home
tptctl patrol baseline             # show baseline summary
tptctl patrol baseline --rebuild   # re-hash everything from scratch
tptctl patrol quarantine list
tptctl patrol quarantine restore <id>

# Shared event log
tptctl events --tail --source guard
```

### Web dashboard

A single-page dashboard is embedded in both daemons and served at the root of
each API listener — open <http://127.0.0.1:7731> (Guard) or
<http://127.0.0.1:7732> (Patrol) in a browser. It talks to both APIs from the
page; if API auth is enabled, paste the bearer token into the token field. A
`GET /health-score` endpoint on both daemons feeds the health widgets and live
event feed.

> Cross-port calls from the dashboard are permitted by a CORS policy that only
> reflects loopback origins, so the two listeners can stay bound to `127.0.0.1`.

---

## Project layout

```
cmd/            Daemon and CLI entry points (tpt-guard, tpt-patrol, tpt-backup, tptctl, tpt-tray)
internal/       Core packages (guard, patrol, backup, api, db, events, threatfeed, quarantine, ...)
web/            Embedded single-page dashboard
config/         Annotated example TOML configs
systemd/        systemd unit files
nsis/ windows/  Windows installer and service assets
```

---

## Releasing

Releases are built by [GoReleaser](https://goreleaser.com/). The config is in
[`.goreleaser.yml`](.goreleaser.yml) and produces:

- `tpt-av_<version>_linux_{amd64,arm64}.tar.gz` — binaries + example configs + systemd units + `install.sh`
- `tpt-av_<version>_windows_amd64.zip` — binaries + example configs + `install.ps1`
- `tpt-av_<version>_checksums.txt`

**To cut a release:**

```sh
# 1. Update CHANGELOG.md — move [Unreleased] entries under the new version
# 2. Tag and push
git tag v0.1.0
git push origin v0.1.0

# 3. Build and publish to GitHub Releases (requires GITHUB_TOKEN in env)
goreleaser release --clean
```

> `tpt-tray` (Windows CGo) is built in GoReleaser but requires a CGo toolchain on
> the build machine. On Linux CI, install `mingw-w64` and set `CC=x86_64-w64-mingw32-gcc`.
> To skip it during development: `goreleaser release --skip=tray-windows --clean`

**Dry run (no publish):**

```sh
make release-dry-run     # goreleaser release --snapshot --clean
```

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a pull request.

## Security

Found a vulnerability? Please follow the disclosure process in
[SECURITY.md](SECURITY.md) — do **not** open a public issue for security reports.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
See [NOTICE](NOTICE) for third-party attributions.

Copyright © 2026 TPT Solutions.
