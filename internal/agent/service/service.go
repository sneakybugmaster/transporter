// Package service installs the agent as a system service: a systemd unit on
// Linux, a launchd daemon on macOS, a Windows service elsewhere.
package service

import (
	"fmt"
	"html"
	"runtime"
	"strings"
)

const (
	// Name identifies the service to systemd and the Windows SCM.
	Name = "transporter"
	// DisplayName is shown in service managers.
	DisplayName = "Transporter mesh agent"
	// LaunchdLabel identifies the macOS launch daemon.
	LaunchdLabel = "com.transporter.agent"
)

// Config describes the service to install.
type Config struct {
	// Exe is the absolute path of the transporter binary.
	Exe string
	// Args follow the binary, starting with "up". They must not contain
	// secrets: the node is enrolled before the service is installed.
	Args []string
}

// SystemdUnit renders the systemd unit file.
func SystemdUnit(c Config) string {
	return fmt.Sprintf(`[Unit]
Description=%s
Documentation=https://github.com/sneakybugmaster/transporter
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=%s
Restart=always
RestartSec=2
# The agent needs to create and configure its TUN interface.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
DeviceAllow=/dev/net/tun rw
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=%s
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`, DisplayName, systemdQuote(append([]string{c.Exe}, c.Args...)), stateDir(c))
}

// LaunchdPlist renders the launch daemon property list.
func LaunchdPlist(c Config) string {
	var args strings.Builder
	for _, a := range append([]string{c.Exe}, c.Args...) {
		fmt.Fprintf(&args, "\t\t<string>%s</string>\n", html.EscapeString(a))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
%s	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>/var/log/transporter.log</string>
</dict>
</plist>
`, LaunchdLabel, args.String())
}

// stateDir finds the --state-dir argument (the unit must be allowed to
// write there).
func stateDir(c Config) string {
	for i, a := range c.Args {
		if (a == "--state-dir" || a == "-state-dir") && i+1 < len(c.Args) {
			return c.Args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "--state-dir="); ok {
			return v
		}
	}
	return "/var/lib/transporter"
}

// systemdQuote quotes a command line for ExecStart.
func systemdQuote(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a != "" && !strings.ContainsAny(a, " \t\"'\\$%;") {
			out[i] = a
			continue
		}
		r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `$$`, `%`, `%%`)
		out[i] = `"` + r.Replace(a) + `"`
	}
	return strings.Join(out, " ")
}

// Supported reports whether service installation works on this OS.
func Supported() bool {
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		return true
	}
	return false
}
