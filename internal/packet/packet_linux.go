//go:build linux

// Package packet adapts Linux raw Ethernet sockets to the scanner interface.
package packet

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/packet"
	"hydrofoon/internal/scan"
)

type client struct{ arp *arp.Client }

func Open(ifi *net.Interface) (scan.PacketIO, error) {
	// Open explicitly so arp.New errors cannot leak the raw socket.
	conn, err := packet.Listen(ifi, packet.Raw, int(ethernet.EtherTypeARP), nil)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, fmt.Errorf("open ARP socket on %s: insufficient privileges; run with sudo or grant the trusted binary CAP_NET_RAW: %w", ifi.Name, err)
		}
		return nil, fmt.Errorf("open ARP socket on %s: %w", ifi.Name, err)
	}
	c, err := arp.New(ifi, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("configure ARP on %s (requires IPv4): %w", ifi.Name, err)
	}
	return &client{arp: c}, nil
}

func (c *client) Request(ip netip.Addr) error {
	if err := c.arp.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	return c.arp.Request(ip)
}

func (c *client) Read() (scan.Reply, error) {
	for {
		p, frame, err := c.arp.Read()
		if err != nil {
			return scan.Reply{}, err
		}
		if !validReply(p, frame) {
			continue
		}
		return scan.Reply{IP: p.SenderIP, MAC: p.SenderHardwareAddr}, nil
	}
}

func validReply(p *arp.Packet, frame *ethernet.Frame) bool {
	return p != nil && frame != nil && p.Operation == arp.OperationReply && p.HardwareType == 1 && p.ProtocolType == uint16(ethernet.EtherTypeIPv4) && p.HardwareAddrLength == 6 && p.IPLength == 4 && p.SenderIP.Is4() && len(p.SenderHardwareAddr) == 6 && bytes.Equal(p.SenderHardwareAddr, frame.Source)
}

func (c *client) Close() error { return c.arp.Close() }
