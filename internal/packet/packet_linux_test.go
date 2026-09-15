//go:build linux

package packet

import (
	"net"
	"net/netip"
	"testing"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
)

func TestReplyValidation(t *testing.T) {
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	p, err := arp.NewPacket(arp.OperationReply, mac, netip.MustParseAddr("10.50.0.1"), mac, netip.MustParseAddr("10.50.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	f := &ethernet.Frame{Source: mac}
	if !validReply(p, f) {
		t.Fatal("valid reply rejected")
	}
	p.Operation = arp.OperationRequest
	if validReply(p, f) {
		t.Fatal("request accepted")
	}
	p.Operation = arp.OperationReply
	f.Source = net.HardwareAddr{2, 0, 0, 0, 0, 2}
	if validReply(p, f) {
		t.Fatal("mismatched Ethernet source accepted")
	}
	f.Source = mac
	p.ProtocolType = uint16(ethernet.EtherTypeIPv6)
	if validReply(p, f) {
		t.Fatal("non-IPv4 accepted")
	}
}
