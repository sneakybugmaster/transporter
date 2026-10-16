package main

import (
	"bytes"
	"strings"
	"testing"
)

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
		{[]string{"up"}, 1, "", "not implemented"},
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
