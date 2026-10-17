//go:build windows

package service

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Install registers and starts the Windows service.
func Install(c Config) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect() //nolint:errcheck // best effort
	if s, err := m.OpenService(Name); err == nil {
		_ = s.Close()
		return errors.New("the service is already installed; run `transporter service uninstall` first")
	}
	s, err := m.CreateService(Name, c.Exe, mgr.Config{
		DisplayName:  DisplayName,
		Description:  "Connects this computer to the Transporter mesh.",
		StartType:    mgr.StartAutomatic,
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		ErrorControl: mgr.ErrorNormal,
	}, c.Args...)
	if err != nil {
		return err
	}
	defer s.Close()
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 2 * time.Second}
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 60)
	return s.Start()
}

// Uninstall stops and removes the Windows service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect() //nolint:errcheck // best effort
	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("service not installed: %w", err)
	}
	defer s.Close()
	if st, err := s.Control(svc.Stop); err == nil {
		for i := 0; i < 50 && st.State != svc.Stopped; i++ {
			time.Sleep(200 * time.Millisecond)
			if st, err = s.Query(); err != nil {
				break
			}
		}
	}
	return s.Delete()
}
