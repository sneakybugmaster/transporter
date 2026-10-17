// Command transporter is the mesh agent and its command-line interface.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/sneakybugmaster/transporter/internal/agent/engine"
	"github.com/sneakybugmaster/transporter/internal/agent/localapi"
	"github.com/sneakybugmaster/transporter/internal/version"
)

const usage = `Transporter mesh agent

Usage:
  transporter <command> [flags]

Commands:
  up        Connect this node to the mesh (runs in the foreground)
  down      Disconnect a running agent
  status    Show connection and peer status
  ping      Measure round-trip time to a peer through the mesh
  service   Install or remove the agent as a system service
  version   Print version information
  help      Show this help

Run "transporter <command> -h" for the flags of a command.
`

func main() {
	if isWindowsService() {
		// Started by the Windows service manager: run `up` with the
		// arguments the service was installed with.
		if err := runWindowsService(os.Args[1:]); err != nil {
			os.Exit(1)
		}
		return
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "transporter", version.String())
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	case "up":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err = cmdUp(ctx, args[1:], stderr)
		stop()
	case "service":
		err = cmdService(args[1:], stdout, stderr)
	case "down":
		err = cmdDown(args[1:], stdout, stderr)
	case "status":
		err = cmdStatus(args[1:], stdout, stderr)
	case "ping":
		err = cmdPing(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func newFlagSet(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("transporter "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", envOr("TRANSPORTER_STATE_DIR", defaultStateDir()), "directory for keys and state (env TRANSPORTER_STATE_DIR)")
	return fs, stateDir
}

func cmdDown(args []string, stdout, stderr io.Writer) error {
	fs, stateDir := newFlagSet("down", stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client(*stateDir).Down(ctx); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "disconnecting")
	return nil
}

func cmdStatus(args []string, stdout, stderr io.Writer) error {
	fs, stateDir := newFlagSet("status", stderr)
	asJSON := fs.Bool("json", false, "print raw JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := client(*stateDir).Status(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}

	e := st.Engine
	state := "connected"
	if !e.Connected {
		state = "connecting"
	}
	fmt.Fprintf(stdout, "%s  %s  %s  coordinator %s (%s)\n", e.Name, strings.Join(e.Addresses, ","), "udp/"+fmt.Sprint(e.ListenPort), st.Coordinator, state)
	if len(e.Endpoints) > 0 {
		fmt.Fprintf(stdout, "endpoints: %s\n", strings.Join(e.Endpoints, ", "))
	}
	if st.Error != "" {
		fmt.Fprintf(stdout, "last error: %s\n", st.Error)
	}
	if len(e.Peers) == 0 {
		fmt.Fprintln(stdout, "\nno peers")
		return nil
	}
	fmt.Fprintln(stdout)
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PEER\tADDRESS\tSTATE\tPATH\tHANDSHAKE\tRX\tTX")
	now := time.Now()
	for _, p := range e.Peers {
		peerState := "offline"
		if p.Online {
			peerState = "online"
		}
		hs := "never"
		if !p.LastHandshake.IsZero() {
			hs = now.Sub(p.LastHandshake).Round(time.Second).String() + " ago"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, strings.Join(p.Addresses, ","), peerState, pathStr(p), hs, bytesStr(p.RxBytes), bytesStr(p.TxBytes))
	}
	return tw.Flush()
}

func cmdPing(args []string, stdout, stderr io.Writer) error {
	fs, stateDir := newFlagSet("ping", stderr)
	count := fs.Int("c", 4, "number of probes")
	timeout := fs.Duration("timeout", 2*time.Second, "time to wait for each reply")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *count < 1 {
		return errors.New("usage: transporter ping [-c N] <peer name or mesh IP>")
	}
	target := fs.Arg(0)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The agent sends the probes, so this works in userspace mode too, where
	// only the agent can reach the mesh.
	var ok, sent int
	var total float64
	header := false
	err := client(*stateDir).Ping(ctx, target, *count, *timeout, func(l localapi.PingResult) {
		switch {
		case l.Seq == 0 && l.Error != "":
			fmt.Fprintf(stdout, "error: %s\n", l.Error)
		case l.Seq == 0:
			// Trailer with the resolved address.
		default:
			if !header {
				fmt.Fprintf(stdout, "PING %s\n", target)
				header = true
			}
			sent++
			if l.Error != "" {
				fmt.Fprintf(stdout, "seq=%d %s\n", l.Seq, l.Error)
				return
			}
			ok++
			total += l.RTTMs
			fmt.Fprintf(stdout, "reply from %s: seq=%d time=%.2fms\n", target, l.Seq, l.RTTMs)
		}
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	if ok == 0 {
		return fmt.Errorf("no replies from %s", target)
	}
	fmt.Fprintf(stdout, "%d/%d replies, avg %.2fms\n", ok, sent, total/float64(ok))
	return nil
}

func pathStr(p engine.PeerStatus) string {
	switch p.Path {
	case "direct":
		return fmt.Sprintf("direct %s (%.1fms)", p.Endpoint, p.LatencyMs)
	case "relay":
		return "relay"
	default:
		return "-"
	}
}

func client(stateDir string) *localapi.Client {
	return localapi.NewClient(filepath.Join(stateDir, localapi.SocketName))
}

func bytesStr(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func envBool(key string) bool {
	v, _ := strconv.ParseBool(os.Getenv(key))
	return v
}

func envBoolOr(key string, def bool) bool {
	v, err := strconv.ParseBool(os.Getenv(key))
	if err != nil {
		return def
	}
	return v
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
