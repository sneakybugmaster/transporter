// Package version holds build metadata injected at link time.
package version

import (
	"fmt"
	"runtime"
)

// Set via -ldflags "-X github.com/sneakybugmaster/transporter/internal/version.Version=..." at build time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Info is the JSON-serialisable form of the build metadata.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"`
}

// Get returns the build metadata of the running binary.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String returns a one-line human readable version string.
func String() string {
	i := Get()
	return fmt.Sprintf("%s (commit %s, built %s, %s, %s)", i.Version, i.Commit, i.Date, i.GoVersion, i.Platform)
}
