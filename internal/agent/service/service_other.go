//go:build !linux && !darwin && !windows

package service

import (
	"errors"
	"runtime"
)

// Install is not supported on this OS.
func Install(Config) error {
	return errors.New("service installation is not supported on " + runtime.GOOS)
}

// Uninstall is not supported on this OS.
func Uninstall() error { return Install(Config{}) }
