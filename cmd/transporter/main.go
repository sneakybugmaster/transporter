// Command transporter is the mesh agent and its command-line interface.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/sneakybugmaster/transporter/internal/version"
)

const usage = `Transporter mesh agent

Usage:
  transporter <command> [flags]

Commands:
  up        Connect this node to the mesh
  down      Disconnect this node from the mesh
  status    Show connection and peer status
  version   Print version information
  help      Show this help
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "transporter", version.String())
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	case "up", "down", "status":
		fmt.Fprintf(stderr, "transporter %s: not implemented yet\n", args[0])
		return 1
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
