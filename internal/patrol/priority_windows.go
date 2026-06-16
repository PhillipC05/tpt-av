//go:build windows

package patrol

import "golang.org/x/sys/windows"

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procSetThreadPriority = kernel32.NewProc("SetThreadPriority")
)

const threadPriorityBelowNormal = uintptr(0xFFFFFFFF) // -1 as DWORD

func setPriority() {
	h, err := windows.GetCurrentThread()
	if err != nil {
		return
	}
	procSetThreadPriority.Call(uintptr(h), threadPriorityBelowNormal)
}
