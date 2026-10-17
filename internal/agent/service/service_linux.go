//go:build linux

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const systemdUnitPath = "/etc/systemd/system/transporter.service"

// Install writes and starts the systemd unit.
func Install(c Config) error {
	if strings.HasPrefix(c.Exe, "/home/") || strings.HasPrefix(c.Exe, "/root/") {
		// The unit sets ProtectHome, so systemd could not even start it.
		return fmt.Errorf("%s is in a home directory, which the service cannot read; install it first, e.g. sudo install %s /usr/local/bin/transporter", c.Exe, c.Exe)
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemd not found: run %s %v under your init system instead", c.Exe, c.Args)
	}
	if err := os.WriteFile(systemdUnitPath, []byte(SystemdUnit(c)), 0o644); err != nil { //nolint:gosec // unit files are world-readable
		return fmt.Errorf("write %s (run as root): %w", systemdUnitPath, err)
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	return run("systemctl", "enable", "--now", Name)
}

// Uninstall stops and removes the systemd unit.
func Uninstall() error {
	_ = run("systemctl", "disable", "--now", Name)
	if err := os.Remove(systemdUnitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return run("systemctl", "daemon-reload")
}

func run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // fixed commands
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}
