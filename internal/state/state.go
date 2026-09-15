// Package state tracks successful scans, keeping enrollment separate from
// observations. Apply is transactional: it returns a new state on success.
package state

import (
	"fmt"
	"math"
	"reflect"
	"sort"
	"time"

	"hydrofoon/internal/inventory"
	"hydrofoon/internal/model"
)

const MaxInterfaces = 65536
const MaxMappings = 262144

type Mapping struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}
type Interface struct {
	MAC         string             `json:"mac"`
	AssetID     string             `json:"asset_id,omitempty"`
	Name        string             `json:"name,omitempty"`
	FirstSeen   time.Time          `json:"first_seen"`
	LastSeen    time.Time          `json:"last_seen"`
	MissedScans uint64             `json:"missed_scans"`
	Status      string             `json:"status"`
	IPs         []string           `json:"ips"`
	Mappings    map[string]Mapping `json:"mappings"`
}
type State struct {
	SchemaVersion int                   `json:"schema_version"`
	Scope         model.Scope           `json:"scope"`
	UpdatedAt     time.Time             `json:"updated_at"`
	Interfaces    map[string]*Interface `json:"interfaces"`
	Conflicts     map[string][]string   `json:"conflicts"`
}

func New(scope model.Scope) *State {
	return &State{SchemaVersion: model.SchemaVersion, Scope: scope, Interfaces: map[string]*Interface{}, Conflicts: map[string][]string{}}
}

func (s *State) clone() *State {
	n := New(s.Scope)
	n.UpdatedAt = s.UpdatedAt
	for mac, v := range s.Interfaces {
		i := *v
		i.IPs = append([]string(nil), v.IPs...)
		i.Mappings = map[string]Mapping{}
		for ip, m := range v.Mappings {
			i.Mappings[ip] = m
		}
		n.Interfaces[mac] = &i
	}
	for ip, macs := range s.Conflicts {
		n.Conflicts[ip] = append([]string(nil), macs...)
	}
	return n
}

type entity struct {
	assetID, name string
	macs          []string
	seen          bool
}

func (s *State) entities() map[string]*entity {
	r := map[string]*entity{}
	for mac, i := range s.Interfaces {
		key := "mac:" + mac
		if i.AssetID != "" {
			key = "asset:" + i.AssetID
		}
		e := r[key]
		if e == nil {
			e = &entity{assetID: i.AssetID, name: i.Name}
			r[key] = e
		}
		e.macs = append(e.macs, mac)
		e.seen = e.seen || i.Status == "seen"
	}
	for _, e := range r {
		sort.Strings(e.macs)
	}
	return r
}

func Event(scope model.Scope, kind string, at time.Time) model.Event {
	return model.Event{SchemaVersion: model.SchemaVersion, Type: kind, Time: model.UTC(at), Scope: scope}
}

func (s *State) Apply(result model.Scan, inv *inventory.Inventory, threshold uint64) (*State, []model.Event, error) {
	if threshold < 1 {
		return nil, nil, fmt.Errorf("stale threshold must be positive")
	}
	if result.Scope != s.Scope || result.SchemaVersion != model.SchemaVersion {
		return nil, nil, fmt.Errorf("scan scope or schema does not match state")
	}
	if result.FinishedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) || result.FinishedAt.Before(s.UpdatedAt) {
		return nil, nil, fmt.Errorf("scan timestamp precedes existing state; check the system clock")
	}
	n := s.clone()
	// Reconcile enrollment before comparing aggregate asset transitions.
	for _, i := range n.Interfaces {
		d, _ := inv.Lookup(i.MAC)
		i.AssetID, i.Name = d.AssetID, d.Name
	}
	before := n.entities()
	seen := map[string]map[string]time.Time{}
	claims := map[string][]string{}
	for _, o := range result.Observations {
		if seen[o.MAC] == nil {
			seen[o.MAC] = map[string]time.Time{}
		}
		if _, exists := seen[o.MAC][o.IP]; !exists {
			claims[o.IP] = append(claims[o.IP], o.MAC)
		}
		seen[o.MAC][o.IP] = o.ObservedAt
	}
	changes := []model.Event{}
	for _, mac := range sortedKeys(seen) {
		ips := sortedKeys(seen[mac])
		model.SortIPs(ips)
		i := n.Interfaces[mac]
		if i == nil {
			d, _ := inv.Lookup(mac)
			i = &Interface{MAC: mac, AssetID: d.AssetID, Name: d.Name, FirstSeen: result.FinishedAt, Mappings: map[string]Mapping{}}
			n.Interfaces[mac] = i
		} else if !reflect.DeepEqual(i.IPs, ips) {
			e := Event(s.Scope, "ip_changed", result.FinishedAt)
			e.AssetID, e.Name, e.MAC = i.AssetID, i.Name, mac
			e.PreviousIPs, e.IPs = i.IPs, ips
			changes = append(changes, e)
		}
		for ip, at := range seen[mac] {
			m, exists := i.Mappings[ip]
			if !exists {
				m.FirstSeen = at
			}
			m.LastSeen = at
			i.Mappings[ip] = m
			if at.Before(i.FirstSeen) {
				i.FirstSeen = at
			}
			if at.After(i.LastSeen) {
				i.LastSeen = at
			}
		}
		i.IPs, i.MissedScans, i.Status = ips, 0, "seen"
	}
	for mac, i := range n.Interfaces {
		if _, ok := seen[mac]; ok {
			continue
		}
		if i.MissedScans < math.MaxUint64 {
			i.MissedScans++
		}
		if i.MissedScans >= threshold {
			i.Status = "stale"
		}
	}
	if len(n.Interfaces) > MaxInterfaces {
		return nil, nil, fmt.Errorf("state exceeds %d interfaces; archive state and start a new file", MaxInterfaces)
	}
	events := []model.Event{}
	after := n.entities()
	for _, key := range sortedKeys(after) {
		e := after[key]
		prev := before[key]
		kind := ""
		switch {
		case prev == nil:
			kind = "device_seen"
		case !prev.seen && e.seen:
			kind = "device_returned"
		case prev.seen && !e.seen:
			kind = "device_stale"
		}
		if kind != "" {
			event := Event(s.Scope, kind, result.FinishedAt)
			event.AssetID, event.Name, event.MACs = e.assetID, e.name, e.macs
			events = append(events, event)
		}
	}
	events = append(events, changes...)
	n.Conflicts = map[string][]string{}
	conflictIPs := sortedKeys(claims)
	model.SortIPs(conflictIPs)
	for _, ip := range conflictIPs {
		macs := claims[ip]
		if len(macs) < 2 {
			continue
		}
		sort.Strings(macs)
		n.Conflicts[ip] = macs
		if !reflect.DeepEqual(s.Conflicts[ip], macs) {
			e := Event(s.Scope, "ip_conflict", result.FinishedAt)
			e.IP, e.MACs = ip, macs
			events = append(events, e)
		}
	}
	n.UpdatedAt = result.FinishedAt
	if err := n.Validate(s.Scope); err != nil {
		return nil, nil, fmt.Errorf("invalid resulting state: %w", err)
	}
	return n, events, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
