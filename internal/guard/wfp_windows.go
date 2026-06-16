//go:build windows

package guard

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tpt-av/tpt-av/internal/config"
)

// applyProcessRules adds per-application outbound rules using netsh advfirewall.
// [[allow.process]] entries limit each named executable to its declared IP list.
func (f *Firewall) applyProcessRules() {
	for i, proc := range f.cfg.Allow.Processes {
		exePath := resolveExePath(proc.Name)
		if exePath == "" {
			continue
		}
		for j, ip := range proc.IPs {
			name := fmt.Sprintf("TPT_PROC_%d_%d", i, j)
			run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
			run("netsh", "advfirewall", "firewall", "add", "rule",
				"name="+name,
				"dir=out",
				"action=allow",
				"program="+exePath,
				"remoteip="+ip,
				"enable=yes")
		}
	}
}

// resolveExePath resolves a process name or absolute path to a full exe path.
func resolveExePath(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	// Try common install locations
	base := name
	if !strings.HasSuffix(strings.ToLower(base), ".exe") {
		base += ".exe"
	}
	for _, dir := range []string{
		`C:\Program Files`,
		`C:\Program Files (x86)`,
		`C:\Windows\System32`,
	} {
		candidate := filepath.Join(dir, base)
		if out, err := exec.Command("cmd", "/c", "if exist \""+candidate+"\" echo y").Output(); err == nil {
			if strings.TrimSpace(string(out)) == "y" {
				return candidate
			}
		}
	}
	return ""
}

// AddProcessRule adds a single per-application firewall rule for the given exe+CIDR pair.
func AddProcessRule(exePath, cidr, ruleName string) error {
	if exePath == "" {
		return nil
	}
	run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	return run("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName,
		"dir=out",
		"action=allow",
		"program="+exePath,
		"remoteip="+cidr,
		"enable=yes")
}

// removeProcessRules deletes all TPT_PROC_ prefixed firewall rules.
func removeProcessRules() {
	out, err := exec.Command("netsh", "advfirewall", "firewall",
		"show", "rule", "name=all", "dir=out").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Rule Name:") {
			ruleName := strings.TrimSpace(strings.TrimPrefix(trimmed, "Rule Name:"))
			if strings.HasPrefix(ruleName, "TPT_PROC_") {
				run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
			}
		}
	}
}

// ApplyProcessRulesFromConfig is called externally when config is reloaded.
func ApplyProcessRulesFromConfig(procs []config.ProcessRule) {
	for i, proc := range procs {
		exePath := resolveExePath(proc.Name)
		if exePath == "" {
			continue
		}
		for j, ip := range proc.IPs {
			name := fmt.Sprintf("TPT_PROC_%d_%d", i, j)
			run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
			run("netsh", "advfirewall", "firewall", "add", "rule",
				"name="+name,
				"dir=out",
				"action=allow",
				"program="+exePath,
				"remoteip="+ip,
				"enable=yes")
		}
	}
}
