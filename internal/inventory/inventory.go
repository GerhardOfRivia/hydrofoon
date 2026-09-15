// Package inventory reads enrollment data without ever modifying it.
package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
	"hydrofoon/internal/model"
)

const MaxFileBytes = 8 << 20

type Device struct {
	AssetID string   `json:"asset_id" yaml:"asset_id"`
	Name    string   `json:"name" yaml:"name"`
	MACs    []string `json:"macs" yaml:"macs"`
}

type File struct {
	Devices []Device `json:"devices" yaml:"devices"`
}
type Inventory struct{ byMAC map[string]Device }

func NormalizeMAC(s string) (string, error) {
	m, err := net.ParseMAC(s)
	if err != nil || len(m) != 6 {
		return "", fmt.Errorf("invalid six-byte MAC address %q", s)
	}
	return m.String(), nil
}

func New(f File) (*Inventory, error) {
	in := &Inventory{byMAC: make(map[string]Device)}
	ids := make(map[string]bool)
	for _, d := range f.Devices {
		d.MACs = append([]string(nil), d.MACs...)
		if strings.TrimSpace(d.AssetID) == "" || strings.TrimSpace(d.AssetID) != d.AssetID {
			return nil, fmt.Errorf("asset_id must be nonempty and have no surrounding whitespace")
		}
		if ids[d.AssetID] {
			return nil, fmt.Errorf("duplicate asset_id %q", d.AssetID)
		}
		ids[d.AssetID] = true
		if len(d.MACs) == 0 {
			return nil, fmt.Errorf("asset %q has no MAC addresses", d.AssetID)
		}
		seen := make(map[string]bool)
		for i, raw := range d.MACs {
			mac, err := NormalizeMAC(raw)
			if err != nil {
				return nil, fmt.Errorf("asset %q: %w", d.AssetID, err)
			}
			if old, ok := in.byMAC[mac]; ok {
				return nil, fmt.Errorf("MAC %s assigned to both %q and %q", mac, old.AssetID, d.AssetID)
			}
			if seen[mac] {
				return nil, fmt.Errorf("duplicate MAC %s in asset %q", mac, d.AssetID)
			}
			seen[mac] = true
			d.MACs[i] = mac
		}
		for _, mac := range d.MACs {
			in.byMAC[mac] = d
		}
	}
	return in, nil
}

func Load(path string) (*Inventory, error) {
	if path == "" {
		return New(File{})
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read inventory: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("inventory exceeds %d bytes", MaxFileBytes)
	}
	var data File
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".yaml" || ext == ".yml" {
		d := yaml.NewDecoder(bytes.NewReader(b))
		d.KnownFields(true)
		err = d.Decode(&data)
		if err == nil {
			var extra any
			if e := d.Decode(&extra); e != io.EOF {
				err = fmt.Errorf("expected one YAML document")
			}
		}
	} else {
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		err = d.Decode(&data)
		if err == nil {
			var extra any
			if e := d.Decode(&extra); e != io.EOF {
				err = fmt.Errorf("expected one JSON document")
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("parse inventory %q: %w", path, err)
	}
	if data.Devices == nil {
		return nil, fmt.Errorf("inventory must contain a devices array (use [] for an empty inventory)")
	}
	return New(data)
}

func (in *Inventory) Lookup(mac string) (Device, bool) {
	if in == nil {
		return Device{}, false
	}
	d, ok := in.byMAC[mac]
	return d, ok
}
func (in *Inventory) Match(obs []model.Observation) {
	for i := range obs {
		d, _ := in.Lookup(obs[i].MAC)
		obs[i].AssetID, obs[i].Name = d.AssetID, d.Name
	}
}
