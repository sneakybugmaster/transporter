//go:build darwin

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const launchdPlist = "/Library/LaunchDaemons/" + LaunchdLabel + ".plist"

// Install writes and loads the launch daemon.
func Install(c Config) error {
	if err := os.WriteFile(launchdPlist, []byte(LaunchdPlist(c)), 0o644); err != nil { //nolint:gosec // launchd requires a readable plist
		return fmt.Errorf("write %s (run with sudo): %w", launchdPlist, err)
	}
	_ = run("launchctl", "bootout", "system/"+LaunchdLabel) // replace an older install
	return run("launchctl", "bootstrap", "system", launchdPlist)
}

// Uninstall unloads and removes the launch daemon.
func Uninstall() error {
	_ = run("launchctl", "bootout", "system/"+LaunchdLabel)
	if err := os.Remove(launchdPlist); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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
