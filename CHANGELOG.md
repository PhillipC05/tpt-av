# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial public release of the TPT-AV endpoint security suite.
- `tpt-guard`: default-deny outbound firewall (nftables/iptables/netsh) with a
  DNS stub resolver and DNS-over-HTTPS support.
- `tpt-patrol`: file-integrity baseline, real-time watcher, process monitor,
  quarantine, and threat-feed lookups (ClamAV, YARA, heuristics, MalwareBazaar,
  VirusTotal, AbuseIPDB, OpenPhish).
- `tpt-backup`: local + Wasabi (S3-compatible) backup daemon with AES-256
  encryption.
- `tptctl`: command-line control tool for Guard, Patrol, and the event log.
- `tpt-tray`: Windows system-tray status icon.
- Ransomware detection, canary/honeypot files, health-score API, weekly security
  digest email, and a bundled web dashboard.
- Cross-platform build tooling: Makefile, GoReleaser config, Docker/Compose,
  systemd units, and Linux/Windows installers.

[Unreleased]: https://github.com/tpt-av/tpt-av/commits/main
