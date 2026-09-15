//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hydrofoon/internal/model"
	"hydrofoon/internal/scan"
	"hydrofoon/internal/state"
)

func testDeps() dependencies {
	return dependencies{clock: scan.RealClock{}, selectNetwork: func(name, cidr string) (*net.Interface, netip.Prefix, error) {
		return &net.Interface{Name: name}, netip.MustParsePrefix("10.50.0.0/24"), nil
	}, scan: func(_ context.Context, _ *net.Interface, s model.Scope, _ netip.Prefix, _ scan.Options) (model.Scan, error) {
		now := model.UTC(time.Now())
		return model.Scan{SchemaVersion: 1, Scope: s, StartedAt: now, FinishedAt: now, Targets: 254, Requests: 254, Observations: []model.Observation{{MAC: "02:11:22:33:44:01", IP: "10.50.0.2", ObservedAt: now, Conflict: true}, {MAC: "02:11:22:33:44:02", IP: "10.50.0.2", ObservedAt: now, Conflict: true}}}, nil
	}}
}

func writeTestInventory(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "inventory.json")
	data := `{"devices":[{"asset_id":"MCP-001","name":"Test platform","macs":["02:11:22:33:44:01","02:11:22:33:44:02"]}]}`
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScanJSONFilteringAndTable(t *testing.T) {
	var out, diag bytes.Buffer
	d := testDeps()
	inventoryPath := writeTestInventory(t)
	err := run(context.Background(), []string{"scan", "--interface", "fake0", "--inventory", inventoryPath, "--mac", "02-11-22-33-44-01", "--json"}, &out, &diag, "test", d)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&out)
	var r model.Scan
	if err := dec.Decode(&r); err != nil {
		t.Fatal(err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatal("not one document")
	}
	if r.SchemaVersion != 1 || r.Targets != 254 || len(r.Observations) != 1 || !r.Observations[0].Conflict || r.Observations[0].AssetID != "MCP-001" || diag.Len() != 0 {
		t.Fatal(r, diag.String())
	}
	out.Reset()
	if err := run(context.Background(), []string{"scan", "--interface", "fake0"}, &out, &diag, "test", d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "unknown") || !strings.Contains(out.String(), "OBSERVED AT") || !strings.Contains(out.String(), "yes") {
		t.Fatal(out.String())
	}
}

func TestHelpVersionAndInvalidArguments(t *testing.T) {
	d := testDeps()
	d.scan = func(context.Context, *net.Interface, model.Scope, netip.Prefix, scan.Options) (model.Scan, error) {
		t.Fatal("unexpected packet I/O")
		return model.Scan{}, nil
	}
	for _, args := range [][]string{{"--help"}, {"scan", "--help"}, {"watch", "--help"}, {"version"}} {
		var out bytes.Buffer
		if err := run(context.Background(), args, &out, io.Discard, "1.2.3", d); err != nil || out.Len() == 0 {
			t.Fatal(args, err)
		}
	}
	for _, args := range [][]string{{"bad"}, {"scan"}, {"scan", "--interface", "fake0", "--mac", "bad"}, {"scan", "--interface", "fake0", "--rate", "NaN"}, {"scan", "--interface", "fake0", "--retries", "-1"}, {"scan", "--interface", "fake0", "--wait", "0s"}, {"scan", "--interface", "fake0", "--max-targets", "2"}, {"watch", "--interface", "fake0", "--interval", "0s"}, {"watch", "--interface", "fake0", "--stale-after", "0"}, {"scan", "--interface", "fake0", "extra"}} {
		if err := run(context.Background(), args, io.Discard, io.Discard, "test", d); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}

type stepClock struct {
	now   time.Time
	sleep func()
}

func (c *stepClock) Now() time.Time { return c.now }
func (c *stepClock) Sleep(ctx context.Context, _ time.Duration) error {
	c.now = c.now.Add(time.Second)
	if c.sleep != nil {
		c.sleep()
	}
	return ctx.Err()
}

func TestWatchFailedScansDoNotAgeState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := testDeps()
	c := &stepClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	d.clock = c
	attempt := 0
	d.scan = func(_ context.Context, _ *net.Interface, s model.Scope, _ netip.Prefix, _ scan.Options) (model.Scan, error) {
		attempt++
		if attempt >= 2 && attempt <= 5 {
			return model.Scan{}, errors.New("injected read failure")
		}
		r := model.Scan{SchemaVersion: 1, Scope: s, StartedAt: c.now, FinishedAt: c.now, Observations: []model.Observation{}}
		if attempt == 1 || attempt == 9 {
			r.Observations = append(r.Observations, model.Observation{IP: "10.50.0.1", MAC: "02:11:22:33:44:01", ObservedAt: c.now})
		}
		return r, nil
	}
	c.sleep = func() {
		if attempt == 9 {
			cancel()
		}
	}
	path := filepath.Join(t.TempDir(), "state.json")
	var out, diag bytes.Buffer
	err := run(ctx, []string{"watch", "--interface", "fake0", "--state", path, "--json"}, &out, &diag, "test", d)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var kinds []string
	dec := json.NewDecoder(&out)
	for {
		var e model.Event
		err := dec.Decode(&e)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, e.Type)
		if e.SchemaVersion != 1 || e.Scope.Interface != "fake0" {
			t.Fatal(e)
		}
	}
	want := "device_seen,scan_error,scan_error,scan_error,scan_error,device_stale,device_returned"
	if strings.Join(kinds, ",") != want {
		t.Fatal(kinds)
	}
	s, err := state.Load(path, model.Scope{Interface: "fake0", CIDR: "10.50.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	i := s.Interfaces["02:11:22:33:44:01"]
	if i.MissedScans != 0 || i.Status != "seen" {
		t.Fatal(i)
	}
	if strings.Count(diag.String(), "scan failed") != 4 {
		t.Fatal(diag.String())
	}
}

func TestCancelledScanPreservesState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := testDeps()
	c := &stepClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	d.clock = c
	path := filepath.Join(t.TempDir(), "state.json")
	calls := 0
	var before []byte
	base := d.scan
	d.scan = func(ctx context.Context, ifi *net.Interface, s model.Scope, p netip.Prefix, o scan.Options) (model.Scan, error) {
		calls++
		if calls == 2 {
			before, _ = os.ReadFile(path)
			cancel()
			return model.Scan{}, context.Canceled
		}
		return base(ctx, ifi, s, p, o)
	}
	var out bytes.Buffer
	err := run(ctx, []string{"watch", "--interface", "fake0", "--state", path, "--json"}, &out, io.Discard, "test", d)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("cancelled scan changed state")
	}
	if !strings.Contains(out.String(), `"type":"scan_error"`) {
		t.Fatal(out.String())
	}
}

func TestMalformedStateAndInventoryCollisionBeforeScanning(t *testing.T) {
	d := testDeps()
	d.scan = func(context.Context, *net.Interface, model.Scope, netip.Prefix, scan.Options) (model.Scan, error) {
		t.Fatal("scanned before validating state")
		return model.Scan{}, nil
	}
	p := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(p, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"watch", "--interface", "fake0", "--state", p}, io.Discard, io.Discard, "test", d); err == nil {
		t.Fatal("accepted malformed state")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "broken" {
		t.Fatal("overwritten")
	}
	inventoryPath := writeTestInventory(t)
	if err := run(context.Background(), []string{"watch", "--interface", "fake0", "--state", inventoryPath, "--inventory", inventoryPath}, io.Discard, io.Discard, "test", d); err == nil || !strings.Contains(err.Error(), "inventory and state/lock files must be separate") {
		t.Fatalf("expected inventory collision error, got %v", err)
	}
}
