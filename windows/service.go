//go:build windows

// Package winsvc provides helpers for installing and running Go programs
// as Windows services. Each daemon binary calls winsvc.Run() in main()
// to detect whether it was started by the SCM and behave accordingly.
package winsvc

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// IsWindowsService reports whether the current process is running as a Windows service.
func IsWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	return err == nil && isSvc
}

// Run executes mainFn either directly (interactive mode) or as a Windows service.
// svcName is the service name registered in the SCM.
func Run(svcName string, mainFn func()) {
	if !IsWindowsService() {
		mainFn()
		return
	}

	if err := svc.Run(svcName, &handler{main: mainFn}); err != nil {
		log.Fatalf("svc.Run: %v", err)
	}
}

type handler struct {
	main func()
}

func (h *handler) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	go h.main()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for req := range r {
		switch req.Cmd {
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
}

// Install registers an executable as a Windows service that auto-starts at boot.
func Install(svcName, displayName, description, exePath string, args []string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.CreateService(svcName, exePath, mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: displayName,
		Description: description,
	}, args...)
	if err != nil {
		return fmt.Errorf("create service %s: %w", svcName, err)
	}
	defer s.Close()
	return nil
}

// Uninstall removes a Windows service (must be stopped first).
func Uninstall(svcName string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", svcName, err)
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service %s: %w", svcName, err)
	}
	return nil
}

// StartService starts a stopped Windows service.
func StartService(svcName string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

// StopService sends a stop control to a running Windows service.
func StopService(svcName string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return err
	}
	defer s.Close()

	_, err = s.Control(svc.Stop)
	if err != nil {
		return err
	}

	timeout := time.Now().Add(10 * time.Second)
	for time.Now().Before(timeout) {
		status, err := s.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("service %s did not stop within 10s", svcName)
}

// SelfExePath returns the absolute path of the current executable.
func SelfExePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Abs(exe)
}
