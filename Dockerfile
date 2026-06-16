# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

# yara-dev is only needed when building with -tags yara (YARA scanning).
# Remove it from the next line if you want a smaller builder image.
RUN apk add --no-cache gcc musl-dev yara-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /out/tpt-guard   ./cmd/tpt-guard  && \
    go build -ldflags="-s -w" -o /out/tpt-patrol  ./cmd/tpt-patrol && \
    go build -ldflags="-s -w" -o /out/tpt-backup  ./cmd/tpt-backup && \
    go build -ldflags="-s -w" -o /out/tptctl      ./cmd/tptctl

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM alpine:latest

# iptables, nftables, and ca-certificates for tpt-guard; yara for scanning
RUN apk add --no-cache iptables ip6tables nftables ca-certificates yara

COPY --from=builder /out/tpt-guard   /usr/local/bin/tpt-guard
COPY --from=builder /out/tpt-patrol  /usr/local/bin/tpt-patrol
COPY --from=builder /out/tpt-backup  /usr/local/bin/tpt-backup
COPY --from=builder /out/tptctl      /usr/local/bin/tptctl
COPY web/static/                     /usr/share/tpt-av/web/

RUN mkdir -p /etc/tpt /var/lib/tpt /var/log/tpt

# Default config files (mount real configs over these at runtime)
COPY config/guard.toml.example  /etc/tpt/guard.toml
COPY config/patrol.toml.example /etc/tpt/patrol.toml
COPY config/backup.toml.example /etc/tpt/backup.toml

EXPOSE 7731 7732

# Override CMD in docker-compose.yml per service
CMD ["/usr/local/bin/tpt-guard"]
