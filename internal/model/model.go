// Package model contains the versioned public observation and event schemas.
package model

import (
	"net/netip"
	"sort"
	"time"
)

const SchemaVersion = 1

type Scope struct {
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
}

type Observation struct {
	AssetID    string    `json:"asset_id,omitempty"`
	Name       string    `json:"name,omitempty"`
	IP         string    `json:"ip"`
	MAC        string    `json:"mac"`
	ObservedAt time.Time `json:"observed_at"`
	Conflict   bool      `json:"conflict"`
}

type Scan struct {
	SchemaVersion int           `json:"schema_version"`
	Scope         Scope         `json:"scope"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Targets       int           `json:"targets"`
	Requests      int           `json:"requests"`
	Observations  []Observation `json:"observations"`
}

type Event struct {
	SchemaVersion int       `json:"schema_version"`
	Type          string    `json:"type"`
	Time          time.Time `json:"time"`
	Scope         Scope     `json:"scope"`
	AssetID       string    `json:"asset_id,omitempty"`
	Name          string    `json:"name,omitempty"`
	MAC           string    `json:"mac,omitempty"`
	MACs          []string  `json:"macs,omitempty"`
	IP            string    `json:"ip,omitempty"`
	IPs           []string  `json:"ips,omitempty"`
	PreviousIPs   []string  `json:"previous_ips,omitempty"`
	Error         string    `json:"error,omitempty"`
}

func SortIPs(ips []string) {
	sort.Slice(ips, func(i, j int) bool { return netip.MustParseAddr(ips[i]).Less(netip.MustParseAddr(ips[j])) })
}

func SortObservations(obs []Observation) {
	sort.Slice(obs, func(i, j int) bool {
		if obs[i].IP != obs[j].IP {
			return netip.MustParseAddr(obs[i].IP).Less(netip.MustParseAddr(obs[j].IP))
		}
		return obs[i].MAC < obs[j].MAC
	})
}

func Filter(obs []Observation, mac string) []Observation {
	result := make([]Observation, 0, len(obs))
	for _, o := range obs {
		if mac == "" || o.MAC == mac {
			result = append(result, o)
		}
	}
	return result
}

func UTC(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }
