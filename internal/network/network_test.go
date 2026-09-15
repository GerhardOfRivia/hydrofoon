package network

import (
	"net"
	"net/netip"
	"testing"
)

func TestTargets(t *testing.T) {
	for _, tt := range []struct {
		cidr, first, last string
		count             int
	}{
		{"10.50.0.0/24", "10.50.0.1", "10.50.0.254", 254},
		{"10.50.0.4/31", "10.50.0.4", "10.50.0.5", 2},
		{"10.50.0.7/32", "10.50.0.7", "10.50.0.7", 1},
		{"255.255.255.254/31", "255.255.255.254", "255.255.255.255", 2},
	} {
		t.Run(tt.cidr, func(t *testing.T) {
			targets, err := Targets(netip.MustParsePrefix(tt.cidr), 4096)
			if err != nil {
				t.Fatal(err)
			}
			if len(targets) != tt.count || targets[0].String() != tt.first || targets[len(targets)-1].String() != tt.last {
				t.Fatalf("bad targets: %v", targets)
			}
		})
	}
	for _, tt := range []struct {
		cidr  string
		limit int
	}{{"0.0.0.0/0", 4096}, {"10.0.0.0/19", 4096}, {"10.0.0.0/24", 0}, {"10.0.0.0/24", HardMaxTargets + 1}, {"::/64", 4096}} {
		if _, err := Targets(netip.MustParsePrefix(tt.cidr), tt.limit); err == nil {
			t.Errorf("accepted %v", tt)
		}
	}
	if got, err := Targets(netip.MustParsePrefix("10.0.0.0/19"), 8192); err != nil || len(got) != 8190 {
		t.Fatalf("explicit limit: %d %v", len(got), err)
	}
}

func TestSelectSubnet(t *testing.T) {
	addr := func(s string) net.Addr { ip, n, _ := net.ParseCIDR(s); n.IP = ip; return n }
	one := []net.Addr{addr("10.50.0.9/24"), addr("10.50.0.10/24"), addr("fe80::1/64")}
	if p, err := SelectSubnet(one, ""); err != nil || p.String() != "10.50.0.0/24" {
		t.Fatalf("%s %v", p, err)
	}
	multi := append(one, addr("10.51.0.1/24"))
	if _, err := SelectSubnet(multi, ""); err == nil {
		t.Fatal("ambiguous subnet accepted")
	}
	if _, err := SelectSubnet(multi, "10.50.0.0/28"); err != nil {
		t.Fatal(err)
	}
	if _, err := SelectSubnet(nil, "10.50.0.0/24"); err == nil {
		t.Fatal("missing IPv4 accepted")
	}
	for _, bad := range []string{"invalid", "::/64", "127.0.0.0/8", "224.0.0.0/24", "0.0.0.0/0"} {
		if _, err := ParseCIDR(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
