//go:build linux

package patrol

import "syscall"

func setPriority() {
	// nice +10 — below normal, avoids competing with user workloads
	syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10)
}
