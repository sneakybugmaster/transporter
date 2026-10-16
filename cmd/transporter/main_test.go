package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sneakybugmaster/transporter/internal/agent/engine"
)

func TestBytesStr(t *testing.T) {
	for n, want := range map[uint64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 20: "5.0 MiB"} {
		if got := bytesStr(n); got != want {
			t.Errorf("bytesStr(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestPathStr(t *testing.T) {
	tests := map[string]engine.PeerStatus{
		"direct 192.0.2.1:41641 (1.5ms)": {Path: "direct", Endpoint: "192.0.2.1:41641", LatencyMs: 1.5},
		"relay":                          {Path: "relay"},
		"-":                              {},
	}
	for want, p := range tests {
		if got := pathStr(p); got != want {
			t.Errorf("pathStr(%+v) = %q, want %q", p, got, want)
		}
	}
}

func TestRun(t *testing.T) {
	tests := []struct {
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{nil, 2, "", "Usage:"},
		{[]string{"version"}, 0, "transporter dev", ""},
		{[]string{"help"}, 0, "Commands:", ""},
		{[]string{"up"}, 1, "", "--coordinator is required"},
		{[]string{"up", "-coordinator", "http://c", "-advertise-endpoints", "bogus"}, 1, "", "invalid advertised endpoint"},
		{[]string{"status", "-state-dir", "/nonexistent"}, 1, "", "agent not running"},
		{[]string{"ping"}, 1, "", "usage: transporter ping"},
		{[]string{"bogus"}, 2, "", `unknown command "bogus"`},
	}
	for _, tt := range tests {
		var stdout, stderr bytes.Buffer
		code := run(tt.args, &stdout, &stderr)
		if code != tt.wantCode {
			t.Errorf("%v: code = %d, want %d", tt.args, code, tt.wantCode)
		}
		if !strings.Contains(stdout.String(), tt.wantStdout) {
			t.Errorf("%v: stdout = %q, want substring %q", tt.args, stdout.String(), tt.wantStdout)
		}
		if !strings.Contains(stderr.String(), tt.wantStderr) {
			t.Errorf("%v: stderr = %q, want substring %q", tt.args, stderr.String(), tt.wantStderr)
		}
	}
}
