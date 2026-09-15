// Package network validates the selected interface and enumerates IPv4 targets.
package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

const DefaultMaxTargets = 4096
const HardMaxTargets = 1 << 20

func ParseCIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("invalid IPv4 CIDR %q", s)
	}
	p = p.Masked()
	// Reject ranges containing special-purpose non-unicast addresses.
	last := lastAddr(p)
	if p.Addr().IsUnspecified() || p.Addr().IsLoopback() || last.IsLoopback() || !p.Addr().IsGlobalUnicast() && !p.Addr().IsLinkLocalUnicast() || !last.IsGlobalUnicast() && !last.IsLinkLocalUnicast() {
		return netip.Prefix{}, fmt.Errorf("CIDR %s must contain unicast IPv4 addresses", p)
	}
	return p, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	n := binary.BigEndian.Uint32(b[:]) | uint32((uint64(1)<<(32-p.Bits()))-1)
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}

func Targets(p netip.Prefix, limit int) ([]netip.Addr, error) {
	if !p.IsValid() || !p.Addr().Is4() {
		return nil, fmt.Errorf("an IPv4 subnet is required")
	}
	if limit < 1 || limit > HardMaxTargets {
		return nil, fmt.Errorf("--max-targets must be between 1 and %d", HardMaxTargets)
	}
	p = p.Masked()
	n := uint64(1) << (32 - p.Bits())
	first := p.Addr()
	if p.Bits() < 31 {
		n -= 2
		first = first.Next()
	}
	if n > uint64(limit) {
		return nil, fmt.Errorf("subnet %s has %d targets, exceeding --max-targets %d; explicitly raise the limit if intended", p, n, limit)
	}
	result := make([]netip.Addr, 0, int(n))
	for i := uint64(0); i < n; i++ {
		result = append(result, first)
		first = first.Next()
	}
	return result, nil
}

// SelectSubnet permits multiple addresses in the same subnet, but never guesses
// between different subnets. An explicit CIDR can be a subset of a local subnet.
func SelectSubnet(addrs []net.Addr, explicit string) (netip.Prefix, error) {
	subnets := make(map[netip.Prefix]bool)
	for _, addr := range addrs {
		p, err := netip.ParsePrefix(addr.String())
		if err == nil && p.Addr().Is4() && !p.Addr().IsUnspecified() && !p.Addr().IsLoopback() && (p.Addr().IsGlobalUnicast() || p.Addr().IsLinkLocalUnicast()) {
			subnets[p.Masked()] = true
		}
	}
	if len(subnets) == 0 {
		return netip.Prefix{}, fmt.Errorf("interface has no usable IPv4 configuration; configure an IPv4 address first")
	}
	if explicit != "" {
		return ParseCIDR(explicit)
	}
	if len(subnets) != 1 {
		return netip.Prefix{}, fmt.Errorf("interface has %d usable IPv4 subnets; specify --cidr", len(subnets))
	}
	for p := range subnets {
		return ParseCIDR(p.String())
	}
	panic("unreachable")
}

func Select(name, cidr string) (*net.Interface, netip.Prefix, error) {
	if name == "" {
		return nil, netip.Prefix{}, fmt.Errorf("--interface is required")
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, netip.Prefix{}, fmt.Errorf("interface %q: %w; choose an existing Ethernet or VLAN interface", name, err)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return nil, netip.Prefix{}, fmt.Errorf("interface %q is down; bring it up first", name)
	}
	if ifi.Flags&net.FlagLoopback != 0 || len(ifi.HardwareAddr) != 6 {
		return nil, netip.Prefix{}, fmt.Errorf("interface %q must have a six-byte Ethernet MAC address", name)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, netip.Prefix{}, fmt.Errorf("read addresses for %q: %w", name, err)
	}
	p, err := SelectSubnet(addrs, cidr)
	return ifi, p, err
}
