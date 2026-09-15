package inventory

import (
	"os"
	"path/filepath"
	"testing"

	"hydrofoon/internal/model"
)

func TestNormalizeMAC(t *testing.T) {
	for _, s := range []string{"02:AB:22:33:44:01", "02-AB-22-33-44-01", "02ab.2233.4401"} {
		got, err := NormalizeMAC(s)
		if err != nil || got != "02:ab:22:33:44:01" {
			t.Fatalf("%q => %q %v", s, got, err)
		}
	}
	for _, s := range []string{"", "bad", "02:11:22:33:44:55:66:77", "02:11:22:33:44"} {
		if _, err := NormalizeMAC(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestValidationAndMatching(t *testing.T) {
	d := Device{AssetID: "MCP-1", Name: "platform", MACs: []string{"02:11:22:33:44:01", "02:11:22:33:44:02"}}
	for _, f := range []File{
		{Devices: []Device{d, d}}, {Devices: []Device{d, {AssetID: "MCP-2", MACs: []string{d.MACs[0]}}}},
		{Devices: []Device{{AssetID: "", MACs: d.MACs}}}, {Devices: []Device{{AssetID: "empty"}}},
		{Devices: []Device{{AssetID: "bad", MACs: []string{"bad"}}}}, {Devices: []Device{{AssetID: "dup", MACs: []string{d.MACs[0], d.MACs[0]}}}},
	} {
		if _, err := New(f); err == nil {
			t.Errorf("accepted %+v", f)
		}
	}
	in, err := New(File{Devices: []Device{d}})
	if err != nil {
		t.Fatal(err)
	}
	obs := []model.Observation{{MAC: d.MACs[0]}, {MAC: d.MACs[1]}, {MAC: "02:11:22:33:44:ff"}}
	in.Match(obs)
	if obs[0].AssetID != "MCP-1" || obs[1].AssetID != "MCP-1" || obs[2].AssetID != "" {
		t.Fatalf("bad full-MAC matching: %+v", obs)
	}
	if got := model.Filter(obs, d.MACs[1]); len(got) != 1 || got[0].MAC != d.MACs[1] {
		t.Fatal(got)
	}
	if got := model.Filter(obs, "missing"); got == nil || len(got) != 0 {
		t.Fatal(got)
	}
}

func TestLoad(t *testing.T) {
	for _, tt := range []struct{ ext, data string }{
		{"json", `{"devices":[{"asset_id":"MCP-001","name":"Test platform","macs":["02:11:22:33:44:01","02:11:22:33:44:02"]}]}`},
		{"yaml", `devices:
  - asset_id: MCP-001
    name: Test platform
    macs:
      - "02:11:22:33:44:01"
      - "02:11:22:33:44:02"
`},
	} {
		t.Run(tt.ext, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "inventory."+tt.ext)
			if err := os.WriteFile(p, []byte(tt.data), 0600); err != nil {
				t.Fatal(err)
			}
			in, err := Load(p)
			if err != nil {
				t.Fatal(err)
			}
			if d, ok := in.Lookup("02:11:22:33:44:02"); !ok || d.AssetID != "MCP-001" {
				t.Fatal(d, ok)
			}
		})
	}
	for _, tt := range []struct{ ext, data string }{
		{"json", `{"devices":[],"typo":1}`}, {"json", `{"devices":[]} {}`}, {"json", `null`}, {"json", `{}`},
		{"yaml", "devices: []\n---\ndevices: []\n"}, {"yaml", "devices: []\ntypo: true\n"}, {"yaml", "devices: []\ndevices: []\n"},
	} {
		p := filepath.Join(t.TempDir(), "inventory."+tt.ext)
		if err := os.WriteFile(p, []byte(tt.data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("accepted %q", tt.data)
		}
	}
}
