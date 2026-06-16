//go:build linux

package guard

import (
	"database/sql"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/tpt-av/tpt-av/internal/config"
	"github.com/tpt-av/tpt-av/internal/events"
)

// Firewall manages outbound firewall rules. Supports nftables (O(1) ipset lookup)
// and falls back to iptables on older kernels. Backend is auto-detected unless
// overridden via [network] backend in config.
type Firewall struct {
	cfg     config.GuardConfig
	db      *sql.DB
	log     *events.Logger
	backend string // "iptables" | "nftables"
}

func NewFirewall(cfg config.GuardConfig, db *sql.DB, log *events.Logger) *Firewall {
	backend := cfg.Network.Backend
	if backend == "" || backend == "auto" {
		if nftAvailable() {
			backend = "nftables"
		} else {
			backend = "iptables"
		}
	}
	return &Firewall{cfg: cfg, db: db, log: log, backend: backend}
}

func (f *Firewall) Apply() error {
	if f.cfg.Network.DefaultPolicy != "deny" {
		return nil
	}
	var err error
	if f.backend == "nftables" {
		err = f.applyNft()
	} else {
		err = f.applyIptables()
	}
	if err != nil {
		return err
	}
	f.log.Write(events.New(events.SourceGuard, "rules_applied", events.Info,
		map[string]string{"policy": f.cfg.Network.DefaultPolicy, "backend": f.backend}))
	return nil
}

func (f *Firewall) applyIptables() error {
	exec.Command("iptables", "-N", "TPT_GUARD").Run()
	exec.Command("iptables", "-F", "TPT_GUARD").Run()
	exec.Command("iptables", "-D", "OUTPUT", "-j", "TPT_GUARD").Run()
	if err := run("iptables", "-I", "OUTPUT", "1", "-j", "TPT_GUARD"); err != nil {
		return fmt.Errorf("iptables OUTPUT jump: %w", err)
	}
	run("iptables", "-A", "TPT_GUARD", "-o", "lo", "-j", "ACCEPT")
	run("iptables", "-A", "TPT_GUARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	for _, ip := range f.cfg.Allow.IPs {
		args := []string{"-A", "TPT_GUARD", "-d", ip.CIDR}
		args = appendPortArgs(args, ip)
		args = append(args, "-j", "ACCEPT")
		run("iptables", args...)
	}
	run("iptables", "-A", "TPT_GUARD", "-j", "DROP")
	return nil
}

// AddAllow inserts an ACCEPT rule for the given CIDR.
func (f *Firewall) AddAllow(cidr, comment string) error {
	if f.backend == "nftables" {
		if err := f.addAllowNft(cidr); err != nil {
			return err
		}
	} else {
		if err := run("iptables", "-I", "TPT_GUARD", "-d", cidr, "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	now := time.Now().Unix()
	_, err := f.db.Exec(
		`INSERT OR REPLACE INTO guard_rules(type,ip_cidr,comment,created_at) VALUES(?,?,?,?)`,
		"ip", cidr, comment, now)
	if err != nil {
		return err
	}
	f.log.Write(events.New(events.SourceGuard, "rule_added", events.Info,
		map[string]string{"type": "ip", "cidr": cidr}))
	return nil
}

// RemoveAllow deletes the ACCEPT rule for the given CIDR.
func (f *Firewall) RemoveAllow(cidr string) error {
	if f.backend == "nftables" {
		f.removeAllowNft(cidr)
	} else {
		run("iptables", "-D", "TPT_GUARD", "-d", cidr, "-j", "ACCEPT")
	}
	_, err := f.db.Exec(`DELETE FROM guard_rules WHERE ip_cidr=?`, cidr)
	if err != nil {
		return err
	}
	f.log.Write(events.New(events.SourceGuard, "rule_removed", events.Info,
		map[string]string{"type": "ip", "cidr": cidr}))
	return nil
}

// BlockCIDR inserts an explicit DROP for geo-blocked ranges (before ACCEPT rules).
func (f *Firewall) BlockCIDR(cidr, comment string) error {
	if f.backend == "nftables" {
		return f.blockCIDRNft(cidr)
	}
	return run("iptables", "-I", "TPT_GUARD", "1", "-d", cidr, "-j", "DROP")
}

// FlushGeoBlocks removes all geo-block DROP rules without touching ACCEPT rules.
func (f *Firewall) FlushGeoBlocks() {
	if f.backend == "nftables" {
		f.flushGeoBlocksNft()
		return
	}
	rows, err := f.db.Query(`SELECT ip_cidr FROM guard_rules WHERE type='geo_block'`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var cidr string
		if rows.Scan(&cidr) == nil {
			run("iptables", "-D", "TPT_GUARD", "-d", cidr, "-j", "DROP")
		}
	}
}

// Flush removes the TPT_GUARD chain entirely.
func (f *Firewall) Flush() {
	if f.backend == "nftables" {
		f.flushNft()
		return
	}
	exec.Command("iptables", "-D", "OUTPUT", "-j", "TPT_GUARD").Run()
	exec.Command("iptables", "-F", "TPT_GUARD").Run()
	exec.Command("iptables", "-X", "TPT_GUARD").Run()
}

// appendPortArgs adds protocol/port flags to an iptables arg slice.
func appendPortArgs(args []string, rule config.IPRule) []string {
	if len(rule.Ports) == 0 {
		return args
	}
	proto := rule.Proto
	if proto == "" {
		proto = "tcp"
	}
	args = append(args, "-p", proto)
	ports := make([]string, len(rule.Ports))
	for i, p := range rule.Ports {
		ports[i] = fmt.Sprintf("%d", p)
	}
	if len(ports) == 1 {
		args = append(args, "--dport", ports[0])
	} else {
		args = append(args, "-m", "multiport", "--dports", strings.Join(ports, ","))
	}
	return args
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w — %s", name, strings.Join(args, " "), err, out)
	}
	return nil
}
