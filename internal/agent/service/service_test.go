package service

import (
	"strings"
	"testing"
)

func TestSystemdUnit(t *testing.T) {
	u := SystemdUnit(Config{
		Exe:  "/usr/local/bin/transporter",
		Args: []string{"up", "--coordinator", "https://mesh.example.com", "--state-dir", "/var/lib/my state", "--hostname", "50%$off"},
	})
	for _, want := range []string{
		`ExecStart=/usr/local/bin/transporter up --coordinator https://mesh.example.com --state-dir "/var/lib/my state" --hostname "50%%$$off"`,
		"ReadWritePaths=/var/lib/my state",
		"AmbientCapabilities=CAP_NET_ADMIN",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
}

func TestLaunchdPlist(t *testing.T) {
	p := LaunchdPlist(Config{Exe: "/usr/local/bin/transporter", Args: []string{"up", "--hostname", "a<b&c"}})
	for _, want := range []string{
		"<string>com.transporter.agent</string>",
		"<string>/usr/local/bin/transporter</string>",
		"<string>a&lt;b&amp;c</string>",
		"<key>KeepAlive</key>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist lacks %q:\n%s", want, p)
		}
	}
}

func TestStateDirDefault(t *testing.T) {
	if got := stateDir(Config{Args: []string{"up"}}); got != "/var/lib/transporter" {
		t.Fatalf("stateDir = %q", got)
	}
	if got := stateDir(Config{Args: []string{"up", "--state-dir=/srv/t"}}); got != "/srv/t" {
		t.Fatalf("stateDir = %q", got)
	}
}
