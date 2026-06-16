#!/usr/bin/env bash
# TPT-AV Linux installer
# Usage:  curl -fsSL https://raw.githubusercontent.com/tpt-av/tpt-av/main/install.sh | bash
# Or:     ./install.sh
set -euo pipefail

REPO="tpt-av/tpt-av"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/tpt"
DATA_DIR="/var/lib/tpt"
LOG_DIR="/var/log/tpt"
SYSTEMD_DIR="/etc/systemd/system"

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  GOARCH="amd64" ;;
  aarch64) GOARCH="arm64" ;;
  *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Determine latest release tag
if command -v curl &>/dev/null; then
  LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
else
  LATEST=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
fi

if [ -z "$LATEST" ]; then
  echo "Error: Could not determine latest release. Check your internet connection."
  exit 1
fi

echo "Installing TPT-AV ${LATEST} (linux/${GOARCH})…"

TARBALL="tpt-av_${LATEST}_linux_${GOARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${TARBALL}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cd "$TMP"
echo "Downloading ${URL}…"
if command -v curl &>/dev/null; then
  curl -fsSL "$URL" -o tpt-av.tar.gz
else
  wget -q "$URL" -O tpt-av.tar.gz
fi

tar -xzf tpt-av.tar.gz

# Install binaries
echo "Installing binaries to ${INSTALL_DIR}…"
install -m 755 tpt-guard   "${INSTALL_DIR}/tpt-guard"
install -m 755 tpt-patrol  "${INSTALL_DIR}/tpt-patrol"
install -m 755 tpt-backup  "${INSTALL_DIR}/tpt-backup"
install -m 755 tptctl      "${INSTALL_DIR}/tptctl"

# Create directories
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
chmod 750 "$CONFIG_DIR" "$DATA_DIR"

# Install default configs (do not overwrite existing)
for f in guard patrol backup; do
  if [ ! -f "${CONFIG_DIR}/${f}.toml" ]; then
    install -m 640 "${f}.toml.example" "${CONFIG_DIR}/${f}.toml"
    echo "Created ${CONFIG_DIR}/${f}.toml — edit before starting the daemons."
  fi
done

# Install and enable systemd units
if systemctl --version &>/dev/null 2>&1; then
  for unit in tpt-guard tpt-patrol tpt-backup; do
    install -m 644 "systemd/${unit}.service" "${SYSTEMD_DIR}/"
  done
  systemctl daemon-reload
  echo ""
  echo "Enable and start with:"
  echo "  systemctl enable --now tpt-guard tpt-patrol"
  echo "  systemctl enable --now tpt-backup   # optional"
fi

echo ""
echo "TPT-AV ${LATEST} installed successfully."
echo "Dashboard: http://127.0.0.1:7731  (once tpt-guard is running)"
