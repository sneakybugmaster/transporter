//go:build windows

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/sneakybugmaster/transporter/internal/agent/service"
)

func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// runWindowsService runs `up` under the service control manager. Logs go to
// agent.log in the state directory (services have no console).
func runWindowsService(args []string) error {
	return svc.Run(service.Name, &winService{args: args})
}

type winService struct{ args []string }

func (w *winService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logw := io.Discard
	if dir := stateDirArg(w.args); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
		if f, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil { //nolint:gosec // state dir from the installed service's own arguments
			defer f.Close()
			logw = f
		}
	}
	done := make(chan error, 1)
	go func() { done <- cmdUp(ctx, w.args[1:], logw) }() // args[0] is "up"

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				return false, 1 // the service manager restarts us
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		}
	}
}

func stateDirArg(args []string) string {
	for i, a := range args {
		if a == "--state-dir" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
