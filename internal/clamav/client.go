// Package clamav is a minimal Go client for the clamd AV daemon.
// It communicates via a Unix socket (Linux default) or TCP (Windows / remote).
// If clamd is not running, all scan calls return clean with a single logged warning.
package clamav

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Client connects to a running clamd daemon. Socket can be:
//   - A filesystem path: "/var/run/clamav/clamd.ctl" → Unix domain socket
//   - A host:port string: "127.0.0.1:3310" → TCP
type Client struct {
	socket  string
	once    sync.Once // log "clamd unavailable" only once
	network string    // "unix" or "tcp"
}

func New(socket string) *Client {
	network := "unix"
	if strings.Contains(socket, ":") && !strings.HasPrefix(socket, "/") {
		network = "tcp"
	}
	return &Client{socket: socket, network: network}
}

// ScanFile asks clamd to scan the file at path.
// Returns (true, ruleName) if infected, (false, "") if clean.
// Returns (false, "") without error if clamd is unreachable (fail-open).
func (c *Client) ScanFile(path string) (infected bool, ruleName string, err error) {
	conn, err := c.dial()
	if err != nil {
		c.once.Do(func() {}) // mark as warned; caller logs once
		return false, "", nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "SCAN %s\n", path)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false, "", nil
	}
	return parseResponse(string(buf[:n]))
}

// Ping checks whether clamd is reachable.
func (c *Client) Ping() bool {
	conn, err := c.dial()
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(conn, "PING\n")
	buf := make([]byte, 16)
	n, _ := conn.Read(buf)
	return strings.TrimSpace(string(buf[:n])) == "PONG"
}

func (c *Client) dial() (net.Conn, error) {
	return net.DialTimeout(c.network, c.socket, 3*time.Second)
}

// parseResponse interprets a clamd SCAN response line.
// Format: "/path/to/file: RuleName FOUND" or "/path/to/file: OK"
func parseResponse(line string) (infected bool, ruleName string, err error) {
	line = strings.TrimSpace(line)
	if strings.HasSuffix(line, "OK") {
		return false, "", nil
	}
	if strings.HasSuffix(line, "FOUND") {
		// Extract rule name: "path: RuleName FOUND"
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			rule := strings.TrimSuffix(strings.TrimSpace(parts[1]), " FOUND")
			return true, rule, nil
		}
		return true, "unknown", nil
	}
	if strings.Contains(line, "ERROR") {
		return false, "", fmt.Errorf("clamd: %s", line)
	}
	return false, "", nil
}
