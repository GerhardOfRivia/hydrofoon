package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"hydrofoon/internal/inventory"
	"hydrofoon/internal/model"
)

var testScope = model.Scope{Interface: "fake0", CIDR: "10.50.0.0/24"}

const macA = "02:11:22:33:44:01"
const macB = "02:11:22:33:44:02"

func stamp(n int) time.Time { return time.Date(2026, 1, 1, 0, 0, n, 0, time.UTC) }
func result(n int, pairs ...string) model.Scan {
	r := model.Scan{SchemaVersion: 1, Scope: testScope, StartedAt: stamp(n), FinishedAt: stamp(n), Observations: []model.Observation{}}
	for j := 0; j < len(pairs); j += 2 {
		r.Observations = append(r.Observations, model.Observation{MAC: pairs[j], IP: pairs[j+1], ObservedAt: stamp(n)})
	}
	return r
}
func testInventory(t *testing.T) *inventory.Inventory {
	t.Helper()
	i, err := inventory.New(inventory.File{Devices: []inventory.Device{{AssetID: "MCP-001", Name: "platform", MACs: []string{macA, macB}}}})
	if err != nil {
		t.Fatal(err)
	}
	return i
}
func kinds(events []model.Event) string {
	var a []string
	for _, e := range events {
		a = append(a, e.Type)
	}
	return strings.Join(a, ",")
}
func apply(t *testing.T, s *State, r model.Scan, i *inventory.Inventory) (*State, []model.Event) {
	t.Helper()
	n, e, err := s.Apply(r, i, 3)
	if err != nil {
		t.Fatal(err)
	}
	return n, e
}

func TestTransitionsAndAssetAggregation(t *testing.T) {
	i := testInventory(t)
	s := New(testScope)
	s, e := apply(t, s, result(0, macA, "10.50.0.1", macB, "10.50.0.2"), i)
	if kinds(e) != "device_seen" || e[0].AssetID != "MCP-001" || len(e[0].MACs) != 2 {
		t.Fatal(e)
	}
	for n := 1; n <= 3; n++ {
		s, e = apply(t, s, result(n, macB, "10.50.0.2"), i)
		if len(e) != 0 {
			t.Fatal(e)
		}
	}
	if s.Interfaces[macA].Status != "stale" || s.Interfaces[macB].Status != "seen" {
		t.Fatal(s.Interfaces)
	}
	for n := 4; n <= 6; n++ {
		s, e = apply(t, s, result(n), i)
		if n < 6 && len(e) != 0 {
			t.Fatal(e)
		}
	}
	if kinds(e) != "device_stale" {
		t.Fatal(e)
	}
	s, e = apply(t, s, result(7), i)
	if len(e) != 0 {
		t.Fatal("repeated stale", e)
	}
	s, e = apply(t, s, result(8, macA, "10.50.0.8", macA, "10.50.0.9"), i)
	if kinds(e) != "device_returned,ip_changed" || !reflect.DeepEqual(e[1].PreviousIPs, []string{"10.50.0.1"}) {
		t.Fatal(e)
	}
	if len(s.Interfaces[macA].Mappings) != 3 || s.Interfaces[macA].FirstSeen != stamp(0) || s.Interfaces[macA].LastSeen != stamp(8) {
		t.Fatal(s.Interfaces[macA])
	}
	s, e = apply(t, s, result(9, macA, "10.50.0.9", macA, "10.50.0.8"), i)
	if len(e) != 0 {
		t.Fatal("order caused change", e)
	}
}

func TestConflictTransitionsAndTransactionalFailure(t *testing.T) {
	s := New(testScope)
	s, e := apply(t, s, result(0, macA, "10.50.0.1", macB, "10.50.0.1"), nil)
	if kinds(e) != "device_seen,device_seen,ip_conflict" {
		t.Fatal(e)
	}
	unchanged, _ := json.Marshal(s)
	bad := result(1)
	bad.Scope.Interface = "other"
	if _, _, err := s.Apply(bad, nil, 3); err == nil {
		t.Fatal("accepted wrong scope")
	}
	if _, _, err := s.Apply(result(-1), nil, 3); err == nil {
		t.Fatal("accepted old timestamp")
	}
	after, _ := json.Marshal(s)
	if string(unchanged) != string(after) {
		t.Fatal("failure mutated state")
	}
	s, e = apply(t, s, result(2, macB, "10.50.0.1", macA, "10.50.0.1"), nil)
	if len(e) != 0 {
		t.Fatal("repeated conflict", e)
	}
	s, e = apply(t, s, result(3, macA, "10.50.0.1"), nil)
	if len(e) != 0 {
		t.Fatal(e)
	}
	_, e = apply(t, s, result(4, macA, "10.50.0.1", macB, "10.50.0.1"), nil)
	if kinds(e) != "ip_conflict" {
		t.Fatal(e)
	}
}

func TestPersistenceAndMalformedState(t *testing.T) {
	s, _ := apply(t, New(testScope), result(0, macA, "10.50.0.1", macB, "10.50.0.1"), testInventory(t))
	p := filepath.Join(t.TempDir(), "state.json")
	if err := Save(p, s); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(p, testScope)
	if err != nil || !reflect.DeepEqual(s, loaded) {
		t.Fatal(loaded, err)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", info.Mode())
	}
	wrong := testScope
	wrong.CIDR = "10.51.0.0/24"
	if _, err := Load(p, wrong); err == nil {
		t.Fatal("conflated networks")
	}
	good, _ := os.ReadFile(p)
	for _, bad := range []string{"{", `null`, string(good) + `{}`, strings.Replace(string(good), `"schema_version": 1`, `"schema_version": 99`, 1), strings.Replace(string(good), `"status": "seen"`, `"status": "online"`, 1), strings.Replace(string(good), `"mac": "02:11:22:33:44:01"`, `"mac": "bad"`, 1)} {
		if err := os.WriteFile(p, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p, testScope); err == nil {
			t.Errorf("accepted malformed state: %s", bad)
		}
		b, _ := os.ReadFile(p)
		if string(b) != bad {
			t.Fatal("malformed file was overwritten")
		}
	}
	if err := Save(p, s); err != nil {
		t.Fatal(err)
	}
	sym := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(p, sym); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(sym, testScope); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestStateLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	release, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if release2, err := Lock(p); err == nil {
		release2()
		t.Fatal("concurrent watch accepted")
	}
}
