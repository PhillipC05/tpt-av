MODULE := github.com/tpt-av/tpt-av
BIN    := bin

.PHONY: all build-linux build-linux-arm64 build-windows build-all \
        build-tray-windows build-yara installer-windows docker-build \
        install-linux clean fmt vet release-dry-run

all: build-linux

# ── Linux ─────────────────────────────────────────────────────────────────────

build-linux:
	@mkdir -p $(BIN)/linux
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN)/linux/tpt-guard    ./cmd/tpt-guard
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN)/linux/tpt-patrol   ./cmd/tpt-patrol
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN)/linux/tpt-backup   ./cmd/tpt-backup
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN)/linux/tptctl       ./cmd/tptctl
	@echo "Linux amd64 binaries → $(BIN)/linux/"

build-linux-arm64:
	@mkdir -p $(BIN)/linux-arm64
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BIN)/linux-arm64/tpt-guard    ./cmd/tpt-guard
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BIN)/linux-arm64/tpt-patrol   ./cmd/tpt-patrol
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BIN)/linux-arm64/tpt-backup   ./cmd/tpt-backup
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BIN)/linux-arm64/tptctl       ./cmd/tptctl
	@echo "Linux arm64 binaries → $(BIN)/linux-arm64/"

# ── Windows ───────────────────────────────────────────────────────────────────

build-windows:
	@mkdir -p $(BIN)/windows
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN)/windows/tpt-guard.exe    ./cmd/tpt-guard
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN)/windows/tpt-patrol.exe   ./cmd/tpt-patrol
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN)/windows/tpt-backup.exe   ./cmd/tpt-backup
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN)/windows/tptctl.exe       ./cmd/tptctl
	@echo "Windows binaries → $(BIN)/windows/"

# tpt-tray requires Windows CGo toolchain (run on Windows or with mingw-w64)
build-tray-windows:
	@mkdir -p $(BIN)/windows
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" \
		-o $(BIN)/windows/tpt-tray.exe ./cmd/tpt-tray
	@echo "Windows tray binary → $(BIN)/windows/tpt-tray.exe"

# NSIS installer — requires makensis in PATH (install from https://nsis.sourceforge.io/)
installer-windows: build-windows
	makensis nsis/installer.nsi
	@echo "Installer → $(BIN)/TPT-AV-Setup.exe"

# ── Docker ────────────────────────────────────────────────────────────────────

docker-build:
	docker build -t tpt-av:latest .
	@echo "Docker image: tpt-av:latest"

docker-up:
	docker compose up -d
	@echo "TPT-AV running via Docker Compose. Dashboard: http://127.0.0.1:7731"

docker-down:
	docker compose down

# ── GoReleaser ────────────────────────────────────────────────────────────────

release-dry-run:
	goreleaser release --snapshot --clean

# ── Install (Linux, runs as root) ─────────────────────────────────────────────

install-linux: build-linux
	install -m 755 $(BIN)/linux/tpt-guard   /usr/local/bin/tpt-guard
	install -m 755 $(BIN)/linux/tpt-patrol  /usr/local/bin/tpt-patrol
	install -m 755 $(BIN)/linux/tpt-backup  /usr/local/bin/tpt-backup
	install -m 755 $(BIN)/linux/tptctl      /usr/local/bin/tptctl
	mkdir -p /etc/tpt /var/lib/tpt /var/log/tpt
	[ -f /etc/tpt/guard.toml  ] || install -m 640 config/guard.toml.example  /etc/tpt/guard.toml
	[ -f /etc/tpt/patrol.toml ] || install -m 640 config/patrol.toml.example /etc/tpt/patrol.toml
	[ -f /etc/tpt/backup.toml ] || install -m 640 config/backup.toml.example /etc/tpt/backup.toml
	install -m 644 systemd/tpt-guard.service   /etc/systemd/system/
	install -m 644 systemd/tpt-patrol.service  /etc/systemd/system/
	install -m 644 systemd/tpt-backup.service  /etc/systemd/system/
	systemctl daemon-reload
	@echo "Installed. Enable with: systemctl enable --now tpt-guard tpt-patrol"
	@echo "Optional:               systemctl enable --now tpt-backup"

# ── Build all platforms ───────────────────────────────────────────────────────

build-all: build-linux build-linux-arm64 build-windows

# ── YARA (CGo, requires libyara-dev) ─────────────────────────────────────────
# Linux: apt install libyara-dev  OR  apk add yara-dev
# Then: make build-yara
build-yara:
	@mkdir -p $(BIN)/linux
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags yara \
		-ldflags="-s -w" -o $(BIN)/linux/tpt-patrol-yara ./cmd/tpt-patrol
	@echo "YARA-enabled tpt-patrol → $(BIN)/linux/tpt-patrol-yara"

# ── Dev helpers ───────────────────────────────────────────────────────────────

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -rf $(BIN)
