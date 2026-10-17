package main

import (
	"bytes"
	"io"
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
		{[]string{"service"}, 1, "", "missing service command"},
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

func TestServiceArgsOmitAuthKey(t *testing.T) {
	cfg, err := parseUp("test", []string{
		"--coordinator", "https://mesh.example.com/", "--authkey", "trk_secret",
		"--state-dir", "/srv/tp", "--userspace", "--hostname", "box",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cfg.serviceArgs(), " ")
	want := "up --coordinator https://mesh.example.com --state-dir /srv/tp --listen-port 41641 --interface transporter0 --log-level info --hostname box --userspace --socks5 127.0.0.1:1055"
	if got != want {
		t.Fatalf("service args:\n got %s\nwant %s", got, want)
	}
	if strings.Contains(got, "trk_secret") {
		t.Fatal("auth key leaked into service args")
	}

	cfg, err = parseUp("test", []string{"--coordinator", "http://c", "--socks5", "off"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(strings.Join(cfg.serviceArgs(), " "), "--socks5 off") {
		t.Fatalf("socks off not preserved: %v", cfg.serviceArgs())
	}
}
