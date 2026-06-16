# TPT-AV Deployment Guide

Production deployment, service management, hardening, upgrades, and removal for
the TPT-AV suite (`tpt-guard`, `tpt-patrol`, `tpt-backup`, `tptctl`, `tpt-tray`).

For a feature overview and quick start, see [README.md](README.md).

> ⚠️ Early-stage software. Stage it in a non-production environment first, and
> read [SECURITY.md](SECURITY.md) before exposing anything.

---

## 1. Architecture at a glance

| Daemon       | Listens on        | Privileges needed                                  |
|--------------|-------------------|----------------------------------------------------|
| `tpt-guard`  | `127.0.0.1:7731`  | `CAP_NET_ADMIN` + `CAP_NET_RAW` (Linux) / Admin    |
| `tpt-patrol` | `127.0.0.1:7732`  | Read access to all watched paths (root recommended)|
| `tpt-backup` | — (no API)        | Read access to backup sources; network egress      |

`tptctl` is a stateless CLI that talks to the daemon APIs. `tpt-tray` is a
Windows-only status icon. All persistent state lives in SQLite; the APIs bind to
loopback by default.

### Standard paths

| Purpose         | Linux              | Windows                          |
|-----------------|--------------------|----------------------------------|
| Binaries        | `/usr/local/bin`   | `%ProgramFiles%\TPT-AV`          |
| Config          | `/etc/tpt`         | `%ProgramData%\TPT`              |
| Data (SQLite)   | `/var/lib/tpt`     | `%ProgramData%\TPT\data`         |
| Logs            | `/var/log/tpt`     | `%ProgramData%\TPT\logs`         |
| API token       | `/etc/tpt/api.token` | `%ProgramData%\TPT\api.token`  |

---

## 2. Linux deployment (systemd)

### 2a. Scripted install (recommended)

```sh
curl -fsSL https://raw.githubusercontent.com/PhillipC05/tpt-av/main/install.sh | sudo sh
```

The script downloads the latest release for your architecture (`amd64`/`arm64`),
installs the four binaries to `/usr/local/bin`, creates the config/data/log
directories, seeds `*.toml` configs from the examples (without overwriting), and
installs the systemd units.

### 2b. From source

```sh
git clone https://github.com/PhillipC05/tpt-av.git
cd tpt-av
make build-linux            # or build-linux-arm64
sudo make install-linux
```

### 2c. Enable and start

```sh
# Edit configs first — daemons should not be started with defaults in production.
sudoedit /etc/tpt/guard.toml
sudoedit /etc/tpt/patrol.toml

sudo systemctl daemon-reload
sudo systemctl enable --now tpt-guard tpt-patrol
sudo systemctl enable --now tpt-backup     # optional, after editing backup.toml
```

### 2d. Required privileges

`tpt-guard` programs the kernel firewall, so it needs network-admin
capabilities. The shipped unit grants them with:

```ini
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
```

`tpt-patrol` runs as `root` so it can read every watched path; narrow this with
a dedicated user plus ACLs if your watched set is limited.

### 2e. Check status / logs

```sh
systemctl status tpt-guard tpt-patrol
journalctl -u tpt-guard -f
journalctl -u tpt-patrol --since "1 hour ago"
tptctl guard status
tptctl patrol status
```

---

## 3. Windows deployment (services)

### 3a. Scripted install (PowerShell as Administrator)

```powershell
irm https://raw.githubusercontent.com/PhillipC05/tpt-av/main/install.ps1 | iex
```

This installs binaries to `%ProgramFiles%\TPT-AV`, adds them to the system PATH,
seeds configs under `%ProgramData%\TPT`, registers `tpt-guard`, `tpt-patrol`,
and `tpt-backup` as automatic-start services, and starts Guard + Patrol.

Alternatively, run the NSIS installer (`nsis/installer.nsi` output) from a
release archive.

### 3b. Service management

```powershell
Get-Service tpt-guard, tpt-patrol, tpt-backup
Start-Service tpt-guard, tpt-patrol
Stop-Service  tpt-patrol
Restart-Service tpt-guard

# Manual registration (if not using the installer):
New-Service -Name tpt-guard -BinaryPathName "C:\Program Files\TPT-AV\tpt-guard.exe" `
  -DisplayName "TPT Guard" -StartupType Automatic
```

### 3c. Logs

Daemon output goes to `%ProgramData%\TPT\logs`. Service start/stop and crash
events are also visible in **Event Viewer → Windows Logs → Application**
(source `tpt-guard` / `tpt-patrol`).

### 3d. System tray

`tpt-tray.exe` is an optional per-user status icon (build with `make build-tray`,
requires a CGo toolchain). It shows Guard/Patrol health and can trigger a scan;
it is not a service — add it to user startup if you want it running on login.

---

## 4. Docker (Linux host)

```sh
docker compose up -d
docker compose logs -f
```

Edit `docker-compose.yml` to mount your config and the host paths Patrol should
watch. Note that full firewall enforcement and the process monitor need
host-level privileges (`--cap-add=NET_ADMIN`, host network/PID namespaces);
inside a default container these features are limited or unavailable. Use Docker
for the scanner/threat-feed/backup roles, and run Guard natively for real
firewall enforcement.

---

## 5. Configuration

Copy and edit the annotated examples in [`config/`](config/):

| File                                                        | Daemon       |
|------------------------------------------------------------|--------------|
| [`config/guard.toml.example`](config/guard.toml.example)   | `tpt-guard`  |
| [`config/patrol.toml.example`](config/patrol.toml.example) | `tpt-patrol` |
| [`config/backup.toml.example`](config/backup.toml.example) | `tpt-backup` |

Daemons take `--config <path>` (the systemd units pass the `/etc/tpt/*.toml`
paths). Backup reads its config from the default config directory.

### API token

When API auth is enabled, daemons read a bearer token from `api.token` in the
config directory. Generate one and lock down its permissions:

```sh
sudo sh -c 'head -c 32 /dev/urandom | base64 > /etc/tpt/api.token'
sudo chmod 600 /etc/tpt/api.token
```

`tptctl` and the web dashboard send this token with each request.

---

## 6. Hardening checklist

- [ ] **Keep APIs on loopback.** Do not bind `0.0.0.0`. If remote access is
      required, front it with an authenticated reverse proxy or SSH tunnel.
- [ ] **Enable API token auth** and store `api.token` with `600`/owner-only perms.
- [ ] **Restrict config/data dirs** — `chmod 750 /etc/tpt /var/lib/tpt`,
      configs `640`. The install script does this; verify after manual installs.
- [ ] **Review the Guard whitelist** before enabling default-deny so you don't
      lock out package managers, update agents, or remote access.
- [ ] **Set up SMTP alerting** and confirm a test alert is delivered.
- [ ] **Configure backup encryption** — set the AES-256 passphrase in
      `backup.toml`; it never leaves the host. Store it somewhere recoverable.
- [ ] **Restrict the Patrol service account** to the paths it must read where
      feasible, instead of running everything as root.

---

## 7. Upgrades

**Linux:** re-run `install.sh` (it pulls the latest release and reinstalls
binaries; existing configs are preserved), then:

```sh
sudo systemctl restart tpt-guard tpt-patrol tpt-backup
```

**Windows:** stop the services, re-run `install.ps1` (or the NSIS installer),
then start them again:

```powershell
Stop-Service tpt-guard, tpt-patrol, tpt-backup
irm https://raw.githubusercontent.com/PhillipC05/tpt-av/main/install.ps1 | iex
Start-Service tpt-guard, tpt-patrol
```

Configs and the SQLite databases are left in place across upgrades. Check
[CHANGELOG.md](CHANGELOG.md) for breaking changes before a major version bump.

---

## 8. Uninstall

**Linux:**

```sh
sudo systemctl disable --now tpt-guard tpt-patrol tpt-backup
sudo rm -f /etc/systemd/system/tpt-{guard,patrol,backup}.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/{tpt-guard,tpt-patrol,tpt-backup,tptctl}
# Remove state/config only if you no longer need baselines, quarantine, history:
sudo rm -rf /etc/tpt /var/lib/tpt /var/log/tpt
```

**Windows (Administrator):**

```powershell
Stop-Service tpt-guard, tpt-patrol, tpt-backup -ErrorAction SilentlyContinue
sc.exe delete tpt-guard
sc.exe delete tpt-patrol
sc.exe delete tpt-backup
Remove-Item -Recurse -Force "$env:ProgramFiles\TPT-AV"
# Optional: Remove-Item -Recurse -Force "$env:ProgramData\TPT"
```

---

## 9. Post-deployment verification

```sh
# Daemons reachable
tptctl guard status
tptctl patrol status

# File-integrity pipeline: modify a watched file, then tail events
tptctl events --tail --source patrol

# Quarantine round-trip
tptctl patrol quarantine list

# Outbound firewall: a non-whitelisted process should be blocked
tptctl guard rules list
```

Confirm a test email alert arrives, and that a scheduled `tpt-backup` run
produces artifacts in your local and/or S3 target.

---

## 10. Troubleshooting

| Symptom                                   | Check                                                            |
|-------------------------------------------|-----------------------------------------------------------------|
| Guard won't start / firewall errors       | Capabilities (`CAP_NET_ADMIN`); on Windows run as Administrator. |
| `tptctl` gets 401 Unauthorized            | API token mismatch — token file vs. what the CLI/dashboard sends.|
| Patrol misses files                       | Path not in watch list, or excluded by extension/path rules.    |
| High CPU during scans                     | Raise `batch_delay_ms`; confirm below-normal priority is active. |
| Legitimate traffic blocked                | Add an allow rule before relying on default-deny.               |
| Backup uploads fail                       | Endpoint/credentials in `backup.toml`; host egress to the S3 endpoint. |
| Dashboard shows no data                   | Open <http://127.0.0.1:7731> (served by Guard) or `:7732` (Patrol); if auth is on, paste the API token. Check both daemons are running. |

Logs: `journalctl -u tpt-<daemon> -f` (Linux) or `%ProgramData%\TPT\logs` /
Event Viewer (Windows).
