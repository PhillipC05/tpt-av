//go:build linux

// Package netmon provides lightweight network connection monitoring.
// It reads OS connection tables (no packet capture) to detect which processes
// are connecting where, alerting on suspicious ports and beaconing behavior.
package netmon

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tpt-av/tpt-av/internal/config"
	"github.com/tpt-av/tpt-av/internal/events"
)

type connection struct {
	localAddr  string
	remoteAddr string
	pid        int
	process    string
}

// Monitor polls /proc/net/tcp periodically and emits events for new or
// suspicious outbound connections.
type Monitor struct {
	cfg      config.NetMonConfig
	log      *events.Logger
	mu       sync.Mutex
	seen     map[string]time.Time          // key: "proc:remote" → first seen
	beacons  map[string][]time.Time        // key: "proc:remote" → timestamps
	stopCh   chan struct{}
}

func New(cfg config.NetMonConfig, log *events.Logger) *Monitor {
	return &Monitor{
		cfg:     cfg,
		log:     log,
		seen:    make(map[string]time.Time),
		beacons: make(map[string][]time.Time),
		stopCh:  make(chan struct{}),
	}
}

func (m *Monitor) Start() {
	if !m.cfg.Enabled {
		return
	}
	interval := time.Duration(m.cfg.PollIntervalS) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	go m.loop(interval)
}

func (m *Monitor) Stop() {
	close(m.stopCh)
}

func (m *Monitor) loop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.poll()
		}
	}
}

const seenTTL = time.Hour

func (m *Monitor) poll() {
	conns := readProcNetTCP()
	conns = append(conns, readProcNetTCP6()...)

	for _, c := range conns {
		m.evaluate(c)
	}
	m.pruneExpired()
}

// pruneExpired removes seen entries that have not had an active connection in
// the last seenTTL. This keeps the map bounded on long-running daemons.
func (m *Monitor) pruneExpired() {
	cutoff := time.Now().Add(-seenTTL)
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, t := range m.seen {
		if t.Before(cutoff) {
			delete(m.seen, key)
			delete(m.beacons, key)
		}
	}
}

func (m *Monitor) evaluate(c connection) {
	key := fmt.Sprintf("%s:%s", c.process, c.remoteAddr)
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	// New connection alert (info); always refresh timestamp so pruneExpired
	// knows which entries are still active.
	isNew := false
	if _, seen := m.seen[key]; !seen {
		isNew = true
	}
	m.seen[key] = now
	if isNew {
		m.log.Write(events.New(events.SourcePatrol, "new_connection", events.Info,
			map[string]string{
				"process": c.process,
				"remote":  c.remoteAddr,
				"pid":     fmt.Sprintf("%d", c.pid),
			}))
	}

	// Suspicious port alert
	host, portStr, _ := net.SplitHostPort(c.remoteAddr)
	_ = host
	if port, err := strconv.Atoi(portStr); err == nil {
		for _, sp := range m.cfg.SuspiciousPorts {
			if port == sp {
				m.log.Write(events.New(events.SourcePatrol, "suspicious_port", events.Warn,
					map[string]string{
						"process": c.process,
						"remote":  c.remoteAddr,
						"port":    portStr,
					}))
				break
			}
		}
	}

	// Beacon detection — same process connecting to same remote repeatedly
	if m.cfg.BeaconThreshold > 0 {
		m.beacons[key] = append(m.beacons[key], now)
		// Prune events older than 60s
		cutoff := now.Add(-60 * time.Second)
		pruned := m.beacons[key][:0]
		for _, t := range m.beacons[key] {
			if t.After(cutoff) {
				pruned = append(pruned, t)
			}
		}
		m.beacons[key] = pruned
		if len(m.beacons[key]) >= m.cfg.BeaconThreshold {
			m.log.Write(events.New(events.SourcePatrol, "connection_beacon", events.Warn,
				map[string]string{
					"process": c.process,
					"remote":  c.remoteAddr,
					"count":   fmt.Sprintf("%d", len(m.beacons[key])),
				}))
			m.beacons[key] = nil // reset after alert
		}
	}
}

// readProcNetTCP parses /proc/net/tcp for established outbound connections.
func readProcNetTCP() []connection {
	return parseProcNet("/proc/net/tcp", false)
}

func readProcNetTCP6() []connection {
	return parseProcNet("/proc/net/tcp6", true)
}

func parseProcNet(path string, ipv6 bool) []connection {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Build inode → pid map once per poll
	inodePID := buildInodePIDMap()

	var conns []connection
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		state, _ := strconv.ParseUint(fields[3], 16, 8)
		if state != 1 { // 1 = TCP_ESTABLISHED
			continue
		}
		local := parseHexAddr(fields[1], ipv6)
		remote := parseHexAddr(fields[2], ipv6)
		if remote == "" {
			continue
		}
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		pid := inodePID[inode]
		proc := pidName(pid)
		conns = append(conns, connection{
			localAddr:  local,
			remoteAddr: remote,
			pid:        pid,
			process:    proc,
		})
	}
	return conns
}

// parseHexAddr converts "0100007F:0050" → "127.0.0.1:80"
func parseHexAddr(hexAddr string, ipv6 bool) string {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	b, err := hex.DecodeString(parts[0])
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return ""
	}
	// Linux stores IPv4 in little-endian 4-byte hex
	if len(b) == 4 {
		ip := net.IP{b[3], b[2], b[1], b[0]}
		port, _ := strconv.ParseUint(parts[1], 16, 16)
		return fmt.Sprintf("%s:%d", ip.String(), port)
	}
	// IPv6 — reverse each 4-byte group
	ip6 := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		ip6[i*4+0] = b[i*4+3]
		ip6[i*4+1] = b[i*4+2]
		ip6[i*4+2] = b[i*4+1]
		ip6[i*4+3] = b[i*4+0]
	}
	port, _ := strconv.ParseUint(parts[1], 16, 16)
	return fmt.Sprintf("[%s]:%d", ip6.String(), port)
}

// buildInodePIDMap scans /proc/*/fd/* to map socket inode → PID.
func buildInodePIDMap() map[uint64]int {
	m := make(map[uint64]int)
	procs, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, link := range procs {
		target, err := os.Readlink(link)
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}
		inodeStr := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		inode, _ := strconv.ParseUint(inodeStr, 10, 64)
		// Extract PID from path /proc/<pid>/fd/<fd>
		parts := strings.Split(link, "/")
		if len(parts) >= 3 {
			pid, _ := strconv.Atoi(parts[2])
			m[inode] = pid
		}
	}
	return m
}

func pidName(pid int) string {
	if pid == 0 {
		return "unknown"
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Sprintf("pid:%d", pid)
	}
	return strings.TrimSpace(string(data))
}
