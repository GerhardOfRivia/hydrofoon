//go:build linux

// Package cli implements command parsing and machine-readable output.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"hydrofoon/internal/inventory"
	"hydrofoon/internal/model"
	"hydrofoon/internal/network"
	"hydrofoon/internal/packet"
	"hydrofoon/internal/scan"
	"hydrofoon/internal/state"
)

type dependencies struct {
	selectNetwork func(string, string) (*net.Interface, netip.Prefix, error)
	scan          func(context.Context, *net.Interface, model.Scope, netip.Prefix, scan.Options) (model.Scan, error)
	clock         scan.Clock
}

func Run(ctx context.Context, args []string, out, diagnostics io.Writer, version string) int {
	d := dependencies{selectNetwork: network.Select, clock: scan.RealClock{}}
	d.scan = func(ctx context.Context, ifi *net.Interface, scope model.Scope, p netip.Prefix, opts scan.Options) (model.Scan, error) {
		pio, err := packet.Open(ifi)
		if err != nil {
			return model.Scan{}, err
		}
		return scan.Run(ctx, pio, scope, p, opts, d.clock)
	}
	err := run(ctx, args, out, diagnostics, version, d)
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	fmt.Fprintf(diagnostics, "hydrofoon: %v\n", err)
	return 1
}

const usage = `Usage: hydrofoon <scan|watch|version> [options]

Discover IPv4 systems on an explicitly authorized local Ethernet/VLAN network.
  scan     Discover once; print a table or one JSON document
  watch    Repeat scans; emit seen/stale and address transitions
  version  Print the build version

Use hydrofoon scan --help or hydrofoon watch --help for options.
`

func run(ctx context.Context, args []string, out, diagnostics io.Writer, version string, d dependencies) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, err := io.WriteString(out, usage)
		return err
	}
	command := args[0]
	if command == "version" {
		if len(args) != 1 {
			return fmt.Errorf("version takes no arguments")
		}
		_, err := fmt.Fprintf(out, "hydrofoon %s\n", version)
		return err
	}
	if command != "scan" && command != "watch" {
		return fmt.Errorf("unknown command %q; use --help", command)
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	iface := fs.String("interface", "", "required Ethernet or VLAN interface")
	cidr := fs.String("cidr", "", "IPv4 subnet (derived only when the interface has one subnet)")
	inventoryPath := fs.String("inventory", "", "read-only JSON or .yaml/.yml enrollment file")
	mac := fs.String("mac", "", "filter output by full MAC after scanning all targets")
	jsonOutput := fs.Bool("json", false, "emit JSON (scan document or watch NDJSON events)")
	rate := fs.Float64("rate", 100, "maximum ARP requests per second (0.1..100000)")
	retries := fs.Int("retries", 1, "additional attempts for unanswered IPs (0..10)")
	wait := fs.Duration("wait", 2*time.Second, "response window between rounds and after final request (up to 1m)")
	maxTargets := fs.Int("max-targets", network.DefaultMaxTargets, "maximum target addresses (hard ceiling 1048576)")
	var statePath string
	var interval time.Duration
	var stale uint64
	if command == "watch" {
		fs.StringVar(&statePath, "state", "", "JSON state file (omit for in-memory tracking)")
		fs.DurationVar(&interval, "interval", 30*time.Second, "delay after each completed scan; scans never overlap")
		fs.Uint64Var(&stale, "stale-after", 3, "missed successful scans before an interface becomes stale")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(out)
			fmt.Fprintf(out, "Usage: hydrofoon %s --interface NAME [options]\n", command)
			fs.PrintDefaults()
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *iface == "" {
		return fmt.Errorf("--interface is required")
	}
	opts := scan.Options{Rate: *rate, Retries: *retries, Wait: *wait, MaxTargets: *maxTargets}
	if err := opts.Validate(); err != nil {
		return err
	}
	if *cidr != "" {
		if _, err := network.ParseCIDR(*cidr); err != nil {
			return err
		}
	}
	if command == "watch" && (interval <= 0 || interval > 24*time.Hour || stale == 0) {
		return fmt.Errorf("--interval must be greater than zero and at most 24h; --stale-after must be positive")
	}
	if *mac != "" {
		normalized, err := inventory.NormalizeMAC(*mac)
		if err != nil {
			return err
		}
		*mac = normalized
	}
	if statePath != "" && *inventoryPath != "" {
		for _, path := range []string{statePath, statePath + ".lock"} {
			if sameFile(path, *inventoryPath) {
				return fmt.Errorf("inventory and state/lock files must be separate")
			}
		}
	}
	inv, err := inventory.Load(*inventoryPath)
	if err != nil {
		return err
	}
	ifi, prefix, err := d.selectNetwork(*iface, *cidr)
	if err != nil {
		return err
	}
	if _, err := network.Targets(prefix, opts.MaxTargets); err != nil {
		return err
	}
	scope := model.Scope{Interface: ifi.Name, CIDR: prefix.Masked().String()}
	if command == "scan" {
		result, err := d.scan(ctx, ifi, scope, prefix, opts)
		if err != nil {
			return err
		}
		inv.Match(result.Observations)
		result.Observations = model.Filter(result.Observations, *mac)
		return writeScan(out, result, *jsonOutput)
	}
	s := state.New(scope)
	if statePath != "" {
		unlock, err := state.Lock(statePath)
		if err != nil {
			return err
		}
		defer unlock()
		s, err = state.Load(statePath, scope)
		if err != nil {
			return err
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, scanErr := d.scan(ctx, ifi, scope, prefix, opts)
		if scanErr != nil {
			e := state.Event(scope, "scan_error", d.clock.Now())
			e.Error = scanErr.Error()
			if err := writeEvent(out, e, *jsonOutput); err != nil {
				return err
			}
			fmt.Fprintf(diagnostics, "hydrofoon: scan failed: %v\n", scanErr)
			if ctx.Err() != nil {
				return ctx.Err()
			}
		} else {
			inv.Match(result.Observations)
			next, events, err := s.Apply(result, inv, stale)
			if err == nil && statePath != "" {
				err = state.Save(statePath, next)
			}
			if err != nil {
				e := state.Event(scope, "scan_error", d.clock.Now())
				e.Error = err.Error()
				if outputErr := writeEvent(out, e, *jsonOutput); outputErr != nil {
					return outputErr
				}
				return fmt.Errorf("update watch state: %w", err)
			}
			s = next
			for _, e := range events {
				if *mac == "" || e.MAC == *mac || slices.Contains(e.MACs, *mac) {
					if err := writeEvent(out, e, *jsonOutput); err != nil {
						return err
					}
				}
			}
		}
		if err := d.clock.Sleep(ctx, interval); err != nil {
			return err
		}
	}
}

func sameFile(a, b string) bool {
	aa, e1 := filepath.Abs(a)
	bb, e2 := filepath.Abs(b)
	if e1 == nil && e2 == nil && aa == bb {
		return true
	}
	ai, e1 := os.Stat(a)
	bi, e2 := os.Stat(b)
	return e1 == nil && e2 == nil && os.SameFile(ai, bi)
}

// Quote control characters from enrollment data so tables cannot inject terminal
// escape sequences or break rows. JSON encoding already escapes them.
func cell(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '�'
		}
		return r
	}, s)
}

func writeScan(w io.Writer, result model.Scan, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(result)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ASSET ID\tNAME\tIP\tMAC\tOBSERVED AT\tCONFLICT")
	for _, o := range result.Observations {
		asset, name := o.AssetID, o.Name
		if asset == "" {
			asset, name = "unknown", "-"
		}
		conflict := ""
		if o.Conflict {
			conflict = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", cell(asset), cell(name), o.IP, o.MAC, o.ObservedAt.Format(time.RFC3339), conflict)
	}
	return tw.Flush()
}

func writeEvent(w io.Writer, e model.Event, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(e)
	}
	identity := e.AssetID
	if identity == "" {
		identity = "unknown"
	}
	_, err := fmt.Fprintf(w, "%s %-16s asset=%s mac=%s macs=%s ip=%s ips=%s previous_ips=%s error=%s\n", e.Time.Format(time.RFC3339), e.Type, cell(identity), e.MAC, strings.Join(e.MACs, ","), e.IP, strings.Join(e.IPs, ","), strings.Join(e.PreviousIPs, ","), cell(e.Error))
	return err
}
