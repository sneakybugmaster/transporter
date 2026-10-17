package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/sneakybugmaster/transporter/internal/agent"
	"github.com/sneakybugmaster/transporter/internal/agent/service"
)

const serviceUsage = `Usage:
  transporter service install [up flags]   Enroll (if --authkey is given) and install as a service
  transporter service uninstall            Stop and remove the service

Needs root (sudo) on Linux and macOS, Administrator on Windows.
`

func cmdService(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, serviceUsage)
		return errors.New("missing service command")
	}
	if !service.Supported() {
		return errors.New("service installation is not supported on this OS")
	}
	switch args[0] {
	case "install":
		cfg, err := parseUp("service install", args[1:], stderr)
		if err != nil {
			return err
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if exe, err = filepath.EvalSymlinks(exe); err != nil {
			return err
		}
		if cfg.opts.AuthKey != "" {
			// Enroll now so the service never needs the auth key.
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cfg.opts.Log = slog.New(slog.NewTextHandler(stderr, nil))
			if err := agent.Enroll(ctx, cfg.opts); err != nil {
				return fmt.Errorf("enroll: %w", err)
			}
		}
		if err := service.Install(service.Config{Exe: exe, Args: cfg.serviceArgs()}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "installed and started the %s service\n", service.Name)
		return nil
	case "uninstall":
		if err := service.Uninstall(); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "removed the %s service\n", service.Name)
		return nil
	default:
		fmt.Fprint(stderr, serviceUsage)
		return fmt.Errorf("unknown service command %q", args[0])
	}
}
