// Package web exposes the compiled configuration UI so it can be embedded into
// the coordinator binary. Run `make web` (or `pnpm build` in this directory)
// before `go build` to include the real UI; otherwise a placeholder is served.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the built UI rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // dist is embedded at compile time, so this cannot fail
	}
	return sub
}
