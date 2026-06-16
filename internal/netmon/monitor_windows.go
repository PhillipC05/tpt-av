//go:build windows

// Package netmon provides lightweight network connection monitoring on Windows.
// Uses GetExtendedTcpTable via golang.org/x/sys/windows to read the connection
// table without packet capture overhead.
package netmon

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/tpt-av/tpt-av/internal/config"
	"github.com/tpt-av/tpt-av/internal/events"
	"golang.org/x/sys/windows"
)

var (
	iphlpapi                  = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable   = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetModuleFileNameExW  = windows.NewLazySystemDLL("psapi.dll").NewProc("GetModuleFileNameExW")
)

const (
	tcpTableOwnerPIDAll = 5 // MIB_TCPTABLE_OWNER_PID, all connections
	afINET              = 2
)

type mibTcpRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type connection struct {
	localAddr  string
	remoteAddr string
	pid        uint32
	process    string
}

// Monitor polls GetExtendedTcpTable periodically.
type Monitor struct {
	cfg     config.NetMonConfig
	log     *events.Logger
	mu      sync.Mutex
	seen    map[string]time.Time
	beacons map[string][]time.Time
	stopCh  chan struct{}
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
	conns := getExtendedTcpTable()
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

	// Always refresh timestamp so pruneExpired knows which entries are still active.
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

	_, portStr, _ := net.SplitHostPort(c.remoteAddr)
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

	if m.cfg.BeaconThreshold > 0 {
		m.beacons[key] = append(m.beacons[key], now)
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
			m.beacons[key] = nil
		}
	}
}

func getExtendedTcpTable() []connection {
	var size uint32
	// First call to get required buffer size
	procGetExtendedTcpTable.Call(
		0, uintptr(unsafe.Pointer(&size)), 1,
		afINET, tcpTableOwnerPIDAll, 0)

	if size == 0 {
		size = 65536
	}
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, afINET, tcpTableOwnerPIDAll, 0)
	if ret != 0 {
		return nil
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	var conns []connection
	const rowSize = 24 // sizeof(MIB_TCPROW_OWNER_PID)
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*rowSize
		if int(offset)+rowSize > len(buf) {
			break
		}
		row := (*mibTcpRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		if row.State != 5 { // MIB_TCP_STATE_ESTAB
			continue
		}
		remoteIP := uint32ToIP(row.RemoteAddr)
		remotePort := uint16BigEndian(uint16(row.RemotePort))
		if remoteIP == "0.0.0.0" {
			continue
		}
		remote := fmt.Sprintf("%s:%d", remoteIP, remotePort)
		proc := pidToName(row.OwningPID)
		conns = append(conns, connection{
			localAddr:  fmt.Sprintf("%s:%d", uint32ToIP(row.LocalAddr), uint16BigEndian(uint16(row.LocalPort))),
			remoteAddr: remote,
			pid:        row.OwningPID,
			process:    proc,
		})
	}
	return conns
}

func uint32ToIP(v uint32) string {
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String()
}

func uint16BigEndian(v uint16) uint16 {
	return (v>>8)&0xff | (v&0xff)<<8
}

func pidToName(pid uint32) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return fmt.Sprintf("pid:%d", pid)
	}
	defer windows.CloseHandle(handle)

	var buf [512]uint16
	r, _, _ := procGetModuleFileNameExW.Call(
		uintptr(handle), 0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)))
	if r == 0 {
		return fmt.Sprintf("pid:%d", pid)
	}
	full := windows.UTF16ToString(buf[:r])
	// Extract just the exe name
	for i := len(full) - 1; i >= 0; i-- {
		if full[i] == '\\' || full[i] == '/' {
			return full[i+1:]
		}
	}
	return full
}
