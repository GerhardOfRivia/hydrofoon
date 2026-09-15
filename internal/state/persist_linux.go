//go:build linux

package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"hydrofoon/internal/inventory"
	"hydrofoon/internal/model"
	"hydrofoon/internal/network"
)

const MaxStateBytes = 64 << 20

// Lock holds a cooperative exclusive lock for the entire watch lifetime. The
// sidecar is deliberately retained: removing it would allow two lock inodes.
func Lock(path string) (func(), error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open state lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("state file is already in use (lock %s): %w", path+".lock", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

func checkFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("state path must be a regular file, not a symlink or directory")
	}
	return nil
}

func Load(path string, scope model.Scope) (*State, error) {
	if err := checkFile(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return New(scope), nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxStateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxStateBytes {
		return nil, fmt.Errorf("state exceeds %d bytes", MaxStateBytes)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var s State
	if err := d.Decode(&s); err != nil {
		return nil, fmt.Errorf("malformed state (left unchanged): %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("state must contain exactly one JSON document (left unchanged)")
	}
	if err := s.Validate(scope); err != nil {
		return nil, fmt.Errorf("invalid state (left unchanged): %w", err)
	}
	return &s, nil
}

func (s *State) Validate(scope model.Scope) error {
	if s.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", s.SchemaVersion)
	}
	if s.Scope != scope || scope.Interface == "" {
		return fmt.Errorf("state scope %+v does not match requested scope %+v; use a separate state file", s.Scope, scope)
	}
	p, err := network.ParseCIDR(scope.CIDR)
	if err != nil || p.String() != scope.CIDR {
		return fmt.Errorf("invalid state subnet")
	}
	if s.Interfaces == nil || s.Conflicts == nil {
		return fmt.Errorf("missing interfaces or conflicts objects")
	}
	if len(s.Interfaces) > MaxInterfaces {
		return fmt.Errorf("too many interfaces")
	}
	validTime := func(t time.Time) bool {
		_, offset := t.Zone()
		return !t.IsZero() && offset == 0 && !t.After(s.UpdatedAt)
	}
	validIP := func(ip string) bool {
		a, e := netip.ParseAddr(ip)
		return e == nil && a.Is4() && a.String() == ip && p.Contains(a)
	}
	count := 0
	for mac, i := range s.Interfaces {
		norm, err := inventory.NormalizeMAC(mac)
		if err != nil || norm != mac || i == nil || i.MAC != mac {
			return fmt.Errorf("invalid interface %q", mac)
		}
		if i.Status != "seen" && i.Status != "stale" || i.Status == "stale" && i.MissedScans == 0 {
			return fmt.Errorf("invalid status for %s", mac)
		}
		if !validTime(i.FirstSeen) || !validTime(i.LastSeen) || i.FirstSeen.After(i.LastSeen) {
			return fmt.Errorf("invalid timestamps for %s", mac)
		}
		if len(i.IPs) == 0 || len(i.Mappings) == 0 {
			return fmt.Errorf("missing IP mappings for %s", mac)
		}
		last := netip.Addr{}
		for _, ip := range i.IPs {
			a, _ := netip.ParseAddr(ip)
			if !validIP(ip) || last.IsValid() && !last.Less(a) {
				return fmt.Errorf("invalid or unsorted IPs for %s", mac)
			}
			if _, ok := i.Mappings[ip]; !ok {
				return fmt.Errorf("missing mapping for %s", ip)
			}
			last = a
		}
		for ip, m := range i.Mappings {
			if !validIP(ip) || !validTime(m.FirstSeen) || !validTime(m.LastSeen) || m.FirstSeen.Before(i.FirstSeen) || m.FirstSeen.After(m.LastSeen) || m.LastSeen.After(i.LastSeen) {
				return fmt.Errorf("invalid historical mapping %s/%s", ip, mac)
			}
		}
		count += len(i.Mappings)
		if count > MaxMappings {
			return fmt.Errorf("state exceeds %d mappings; archive it and start a new file", MaxMappings)
		}
	}
	if len(s.Interfaces) > 0 && !validTime(s.UpdatedAt) {
		return fmt.Errorf("invalid updated_at")
	}
	for ip, macs := range s.Conflicts {
		if !validIP(ip) || len(macs) < 2 || !sort.StringsAreSorted(macs) {
			return fmt.Errorf("invalid conflict for %s", ip)
		}
		for j, mac := range macs {
			i := s.Interfaces[mac]
			if i == nil || j > 0 && mac == macs[j-1] || i.MissedScans != 0 {
				return fmt.Errorf("invalid conflict participant %s", mac)
			}
			found := false
			for _, x := range i.IPs {
				found = found || x == ip
			}
			if !found {
				return fmt.Errorf("conflict mapping missing")
			}
		}
	}
	return nil
}

func Save(path string, s *State) error {
	if err := s.Validate(s.Scope); err != nil {
		return err
	}
	if err := checkFile(path); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if len(b) > MaxStateBytes {
		return fmt.Errorf("state exceeds %d bytes", MaxStateBytes)
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".hydrofoon-state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
