//go:build linux

package patrol

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/tpt-av/tpt-av/internal/events"
)

// ProcessMonitor watches for new process exec events via the Linux
// kernel connector (netlink NETLINK_CONNECTOR / CN_IDX_PROC).
type ProcessMonitor struct {
	db     *sql.DB
	log    events.Writer
	feed   ThreatChecker
	stopCh chan struct{}
	fd     int
}

func NewProcessMonitor(db *sql.DB, log events.Writer, feed ThreatChecker) *ProcessMonitor {
	return &ProcessMonitor{db: db, log: log, feed: feed, stopCh: make(chan struct{})}
}

func (pm *ProcessMonitor) Start() error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_CONNECTOR)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	pm.fd = fd

	addr := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1}
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("netlink bind: %w", err)
	}

	// Subscribe to proc events (CN_IDX_PROC=1, CN_VAL_PROC=1)
	if err := pm.subscribe(fd); err != nil {
		syscall.Close(fd)
		return err
	}

	go pm.loop()
	return nil
}

func (pm *ProcessMonitor) Stop() {
	close(pm.stopCh)
	syscall.Close(pm.fd)
}

func (pm *ProcessMonitor) loop() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-pm.stopCh:
			return
		default:
		}
		n, _, err := syscall.Recvfrom(pm.fd, buf, 0)
		if err != nil || n == 0 {
			continue
		}
		pm.handle(buf[:n])
	}
}

// procEventExec is the what=PROC_EVENT_EXEC (0x00000004) payload.
const procEventExec = 0x00000004

func (pm *ProcessMonitor) handle(buf []byte) {
	// Netlink message header is 16 bytes; connector header is 20 bytes.
	// proc_event what field starts at offset 16+20+4 = 40.
	if len(buf) < 48 {
		return
	}
	what := binary.LittleEndian.Uint32(buf[40:44])
	if what != procEventExec {
		return
	}
	pid := int(binary.LittleEndian.Uint32(buf[44:48]))
	go pm.inspectPID(pid)
}

func (pm *ProcessMonitor) inspectPID(pid int) {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return
	}
	name := filepath.Base(exePath)

	hash, err := HashFile(exePath)
	if err != nil {
		return
	}

	// Check against process baseline
	row := pm.db.QueryRow(`SELECT exe_hash FROM process_baseline WHERE exe_path=?`, exePath)
	var baseHash string
	anomaly := false
	if err := row.Scan(&baseHash); err != nil {
		// New executable — not in baseline
		pm.log.Write(events.New(events.SourcePatrol, "process_created", events.Info,
			map[string]string{"pid": fmt.Sprintf("%d", pid), "name": name, "exe": exePath, "hash": hash}))
	} else if hash != baseHash {
		anomaly = true
		pm.log.Write(events.New(events.SourcePatrol, "process_anomaly", events.Warn,
			map[string]string{
				"pid": fmt.Sprintf("%d", pid), "name": name, "exe": exePath,
				"old_hash": baseHash, "new_hash": hash,
			}))
	}

	if anomaly && pm.feed != nil {
		verdict, source, err := pm.feed.Check(hash)
		if err == nil && verdict != "clean" {
			pm.log.Write(events.New(events.SourcePatrol, "threat_detected", events.Critical,
				map[string]string{"path": exePath, "hash": hash, "verdict": verdict, "source": source}))
		}
	}
}

// subscribe sends the CN_PROC_LISTEN command to activate proc event delivery.
func (pm *ProcessMonitor) subscribe(fd int) error {
	// Build: nlmsghdr + cn_msg + proc_cn_mcast_op(PROC_CN_MCAST_LISTEN=1)
	const (
		nlmsgLen  = 16
		cnMsgLen  = 20
		opLen     = 4
		totalLen  = nlmsgLen + cnMsgLen + opLen
	)
	msg := make([]byte, totalLen)
	// nlmsghdr
	binary.LittleEndian.PutUint32(msg[0:4], totalLen)  // nlmsg_len
	binary.LittleEndian.PutUint16(msg[4:6], 0x10)      // nlmsg_type = NLMSG_DONE
	binary.LittleEndian.PutUint16(msg[6:8], 0)         // flags
	binary.LittleEndian.PutUint32(msg[8:12], 0)        // seq
	binary.LittleEndian.PutUint32(msg[12:16], 0)       // pid
	// cn_msg: idx=1 (CN_IDX_PROC), val=1 (CN_VAL_PROC)
	binary.LittleEndian.PutUint32(msg[16:20], 1)       // idx
	binary.LittleEndian.PutUint32(msg[20:24], 1)       // val
	binary.LittleEndian.PutUint32(msg[28:32], opLen)   // len
	// PROC_CN_MCAST_LISTEN = 1
	binary.LittleEndian.PutUint32(msg[36:40], 1)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	return syscall.Sendto(fd, msg, 0, sa)
}
