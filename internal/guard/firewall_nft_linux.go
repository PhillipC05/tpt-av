//go:build linux

package guard

import (
	"fmt"
	"os/exec"
	"strings"
)

func nftAvailable() bool {
	return exec.Command("nft", "--version").Run() == nil
}

func (f *Firewall) applyNft() error {
	// Drop and recreate our table
	exec.Command("nft", "delete", "table", "ip", "tpt_guard").Run()
	if err := run("nft", "add", "table", "ip", "tpt_guard"); err != nil {
		return err
	}

	// Hash set of allowed destination CIDRs (O(1) lookup)
	if err := run("nft", "add", "set", "ip", "tpt_guard", "tpt_allow",
		"{ type ipv4_addr; flags interval; }"); err != nil {
		return fmt.Errorf("nft add set tpt_allow: %w", err)
	}

	// Separate set for geo-blocked CIDRs — checked before tpt_allow
	run("nft", "add", "set", "ip", "tpt_guard", "tpt_block",
		"{ type ipv4_addr; flags interval; }")

	// Populate allow set from config
	for _, ip := range f.cfg.Allow.IPs {
		cidr := nftNormCIDR(ip.CIDR)
		run("nft", "add", "element", "ip", "tpt_guard", "tpt_allow", "{", cidr, "}")
	}

	// Output chain: default policy drop
	if err := run("nft", "add", "chain", "ip", "tpt_guard", "output",
		"{ type filter hook output priority 0; policy drop; }"); err != nil {
		return fmt.Errorf("nft add chain: %w", err)
	}

	// Allow loopback
	run("nft", "add", "rule", "ip", "tpt_guard", "output", "oif", "lo", "accept")
	// Allow established/related
	run("nft", "add", "rule", "ip", "tpt_guard", "output",
		"ct", "state", "established,related", "accept")
	// Drop geo-blocked IPs (checked before allow list)
	run("nft", "add", "rule", "ip", "tpt_guard", "output",
		"ip", "daddr", "@tpt_block", "drop")
	// Accept whitelisted IPs
	run("nft", "add", "rule", "ip", "tpt_guard", "output",
		"ip", "daddr", "@tpt_allow", "accept")

	return nil
}

func (f *Firewall) addAllowNft(cidr string) error {
	cidr = nftNormCIDR(cidr)
	if err := run("nft", "add", "element", "ip", "tpt_guard", "tpt_allow", "{", cidr, "}"); err != nil {
		return fmt.Errorf("nft add element: %w", err)
	}
	return nil
}

func (f *Firewall) removeAllowNft(cidr string) error {
	cidr = nftNormCIDR(cidr)
	run("nft", "delete", "element", "ip", "tpt_guard", "tpt_allow", "{", cidr, "}")
	return nil
}

func (f *Firewall) blockCIDRNft(cidr string) error {
	cidr = nftNormCIDR(cidr)
	return run("nft", "add", "element", "ip", "tpt_guard", "tpt_block", "{", cidr, "}")
}

func (f *Firewall) flushGeoBlocksNft() {
	run("nft", "flush", "set", "ip", "tpt_guard", "tpt_block")
}

func (f *Firewall) flushNft() {
	exec.Command("nft", "delete", "table", "ip", "tpt_guard").Run()
}

func nftNormCIDR(cidr string) string {
	if !strings.Contains(cidr, "/") {
		return cidr + "/32"
	}
	return cidr
}
