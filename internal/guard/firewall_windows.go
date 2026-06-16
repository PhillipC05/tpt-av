//go:build windows

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

// Firewall on Windows uses netsh advfirewall for outbound whitelist rules.
// Per-process rules are enforced via the program= attribute (handled in wfp_windows.go).
type Firewall struct {
	cfg config.GuardConfig
	db  *sql.DB
	log *events.Logger
}

func NewFirewall(cfg config.GuardConfig, db *sql.DB, log *events.Logger) *Firewall {
	return &Firewall{cfg: cfg, db: db, log: log}
}

func (f *Firewall) Apply() error {
	if f.cfg.Network.DefaultPolicy != "deny" {
		return nil
	}

	if err := run("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
		"blockinbound,blockoutbound"); err != nil {
		return fmt.Errorf("set default deny: %w", err)
	}

	for i, ip := range f.cfg.Allow.IPs {
		name := fmt.Sprintf("TPT_ALLOW_%d", i)
		run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
		args := []string{"advfirewall", "firewall", "add", "rule",
			"name=" + name, "dir=out", "action=allow",
			"remoteip=" + ip.CIDR, "enable=yes"}
		if len(ip.Ports) > 0 {
			proto := ip.Proto
			if proto == "" {
				proto = "tcp"
			}
			args = append(args, "protocol="+proto)
			ports := make([]string, len(ip.Ports))
			for j, p := range ip.Ports {
				ports[j] = fmt.Sprintf("%d", p)
			}
			args = append(args, "remoteport="+strings.Join(ports, ","))
		}
		run("netsh", args...)
	}

	// Per-process rules from [[allow.process]]
	f.applyProcessRules()

	f.log.Write(events.New(events.SourceGuard, "rules_applied", events.Info,
		map[string]string{"policy": "deny", "platform": "windows"}))
	return nil
}

func (f *Firewall) AddAllow(cidr, comment string) error {
	name := "TPT_ALLOW_" + strings.ReplaceAll(cidr, "/", "_")
	if err := run("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name, "dir=out", "action=allow", "remoteip="+cidr, "enable=yes"); err != nil {
		return err
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

func (f *Firewall) RemoveAllow(cidr string) error {
	name := "TPT_ALLOW_" + strings.ReplaceAll(cidr, "/", "_")
	run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
	_, err := f.db.Exec(`DELETE FROM guard_rules WHERE ip_cidr=?`, cidr)
	if err != nil {
		return err
	}
	f.log.Write(events.New(events.SourceGuard, "rule_removed", events.Info,
		map[string]string{"type": "ip", "cidr": cidr}))
	return nil
}

// BlockCIDR adds a block rule for geo-blocked ranges.
func (f *Firewall) BlockCIDR(cidr, comment string) error {
	name := "TPT_GEO_" + strings.ReplaceAll(cidr, "/", "_")
	return run("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name, "dir=out", "action=block", "remoteip="+cidr, "enable=yes")
}

// FlushGeoBlocks removes all TPT_GEO_ prefixed rules.
func (f *Firewall) FlushGeoBlocks() {
	rows, err := f.db.Query(`SELECT ip_cidr FROM guard_rules WHERE type='geo_block'`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var cidr string
		if rows.Scan(&cidr) == nil {
			name := "TPT_GEO_" + strings.ReplaceAll(cidr, "/", "_")
			run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
		}
	}
}

func (f *Firewall) Flush() {
	exec.Command("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
		"blockinbound,allowoutbound").Run()
	// Remove only TPT_ prefixed rules, not user rules
	rows, _ := f.db.Query(`SELECT ip_cidr FROM guard_rules`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cidr string
			if rows.Scan(&cidr) == nil {
				n1 := "TPT_ALLOW_" + strings.ReplaceAll(cidr, "/", "_")
				n2 := "TPT_GEO_" + strings.ReplaceAll(cidr, "/", "_")
				run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+n1)
				run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+n2)
			}
		}
	}
	removeProcessRules()
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w — %s", name, strings.Join(args, " "), err, out)
	}
	return nil
}
