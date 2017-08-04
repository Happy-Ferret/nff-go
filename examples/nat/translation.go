// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"fmt"
	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"sync"
	"time"
	"unsafe"
)

type Tuple struct {
	addr    uint32
	port    uint16
}

func (t *Tuple) String() string {
	return fmt.Sprintf("addr = %d.%d.%d.%d:%d",
		t.addr & 0xff,
		(t.addr >> 8) & 0xff,
		(t.addr >> 16) & 0xff,
		(t.addr >> 24) & 0xff,
		t.port)
}

var (
	PublicMAC, PrivateMAC [common.EtherAddrLen]uint8
	Natconfig             *Config
	// Main lookup table which contains entries
	table                 []sync.Map
	mutex                 sync.Mutex

	EMPTY_ENTRY = Tuple{ addr: 0, port: 0, }

	debug bool = false
	loggedDrop int = 0
	loggedAdd int = 0
	loggedDelete int = 0
	loggedPri2PubLookup int = 0
)

func init() {
	table = make([]sync.Map, common.UDPNumber + 1)
}

func allocateNewEgressConnection(protocol uint8, privEntry Tuple, publicAddr uint32) Tuple {
	mutex.Lock()
	t := &table[protocol]

	pubEntry := Tuple{
		addr: publicAddr,
		port: uint16(allocNewPort(protocol)),
	}

	portmap[protocol][pubEntry.port].lastused = time.Now()
	portmap[protocol][pubEntry.port].addr = publicAddr

	t.Store(privEntry, pubEntry)
	t.Store(pubEntry, privEntry)

	if debug && loggedAdd < 100 {
		println("Added new connection:", privEntry.String(), "->", pubEntry.String(), "table", &table[protocol])
		loggedAdd++
	}

	mutex.Unlock()
	return pubEntry
}

// Ingress translation
func PublicToPrivateTranslation(pkt *packet.Packet, ctx flow.UserContext) bool {
	l3offset := pkt.ParseL2()
	var l4offset int

	// Parse packet type and address
	if pkt.Ether.EtherType == packet.SwapBytesUint16(common.IPV4Number) {
		pkt.IPv4 = (*packet.IPv4Hdr)(unsafe.Pointer(pkt.Unparsed + uintptr(l3offset)))
		l4offset = l3offset + int((pkt.IPv4.VersionIhl & 0x0f) << 2)
	} else {
		// We don't currently support anything except for IPv4
		return false
	}

	// Create a lookup key
	protocol := pkt.IPv4.NextProtoID
	pub2priKey := Tuple{
		addr: pkt.IPv4.DstAddr,
	}
	// Parse packet destination port
	if protocol == common.TCPNumber {
		pkt.TCP = (*packet.TCPHdr)(unsafe.Pointer(pkt.Unparsed + uintptr(l4offset)))
		pub2priKey.port = packet.SwapBytesUint16(pkt.TCP.DstPort)
	} else if protocol == common.UDPNumber {
		pkt.UDP = (*packet.UDPHdr)(unsafe.Pointer(pkt.Unparsed + uintptr(l4offset)))
		pub2priKey.port = packet.SwapBytesUint16(pkt.UDP.DstPort)
	} else if protocol == common.ICMPNumber {
		pkt.ICMP = (*packet.ICMPHdr)(unsafe.Pointer(pkt.Unparsed + uintptr(l4offset)))
		pub2priKey.port = pkt.ICMP.Identifier
	} else {
		return false
	}

	// Do lookup
	v, found := table[protocol].Load(pub2priKey)
	// For ingress connections packets are allowed only if a
	// connection has been previosly established with a egress
	// (private to public) packet. So if lookup fails, this incoming
	// packet is ignored.
	if !found {
		if debug && loggedDrop < 100 {
			println("Drop public2private packet because key",
				pub2priKey.String(), "was not found")
			loggedDrop++
		}
		return false
	} else {
		value := v.(Tuple)
		// Check whether connection is too old
		if portmap[protocol][pub2priKey.port].lastused.Add(CONNECTION_TIMEOUT).After(time.Now()) {
			portmap[protocol][pub2priKey.port].lastused = time.Now()
		} else {
			// There was no transfer on this port for too long
			// time. We don't allow it any more
			mutex.Lock()
			deleteOldConnection(protocol, int(pub2priKey.port))
			mutex.Unlock()
			return false
		}

		// Do packet translation
		pkt.Ether.DAddr = Natconfig.PrivatePort.DstMACAddress
		pkt.Ether.SAddr = PrivateMAC
		pkt.IPv4.DstAddr = value.addr

		if pkt.IPv4.NextProtoID == common.TCPNumber {
			pkt.TCP.DstPort = packet.SwapBytesUint16(value.port)
		} else if pkt.IPv4.NextProtoID == common.UDPNumber {
			pkt.UDP.DstPort = packet.SwapBytesUint16(value.port)
		} else {
			// Only address is not modified in ICMP packets
		}

		return true
	}
}

// Egress translation
func PrivateToPublicTranslation(pkt *packet.Packet, ctx flow.UserContext) bool {
	l3offset := pkt.ParseL2()
	var l4offset int

	// Parse packet type and address
	if pkt.Ether.EtherType == packet.SwapBytesUint16(common.IPV4Number) {
		pkt.IPv4 = (*packet.IPv4Hdr)(unsafe.Pointer(pkt.Unparsed + uintptr(l3offset)))
		l4offset = l3offset + int((pkt.IPv4.VersionIhl & 0x0f) << 2)
	} else {
		// We don't currently support anything except for IPv4
		return false
	}

	// Create a lookup key
	protocol := pkt.IPv4.NextProtoID
	pri2pubKey := Tuple{
		addr: pkt.IPv4.SrcAddr,
	}

	// Parse packet source port
	if protocol == common.TCPNumber {
		pkt.TCP = (*packet.TCPHdr)(unsafe.Pointer(pkt.Unparsed + uintptr(l4offset)))
		pri2pubKey.port = packet.SwapBytesUint16(pkt.TCP.SrcPort)
	} else if protocol == common.UDPNumber {
		pkt.UDP = (*packet.UDPHdr)(unsafe.Pointer(pkt.Unparsed + uintptr(l4offset)))
		pri2pubKey.port = packet.SwapBytesUint16(pkt.UDP.SrcPort)
	} else if protocol == common.ICMPNumber {
		pkt.ICMP = (*packet.ICMPHdr)(unsafe.Pointer(pkt.Unparsed + uintptr(l4offset)))
		pri2pubKey.port = pkt.ICMP.Identifier
	} else {
		return false
	}

	// Do lookup
	var value Tuple
	v, found := table[protocol].Load(pri2pubKey)
	if debug && loggedPri2PubLookup < 100 {
		println("Lookup", pri2pubKey.String(), "found =", found, "table =", &table[protocol])
		loggedPri2PubLookup++
	}
	if !found {
		value = allocateNewEgressConnection(protocol, pri2pubKey,
			Natconfig.PublicPort.Subnet.Addr)
	} else {
		value = v.(Tuple)
		portmap[protocol][value.port].lastused = time.Now()
	}

	// Do packet translation
	pkt.Ether.DAddr = Natconfig.PublicPort.DstMACAddress
	pkt.Ether.SAddr = PublicMAC
	pkt.IPv4.SrcAddr = value.addr

	if pkt.IPv4.NextProtoID == common.TCPNumber {
		pkt.TCP.SrcPort = packet.SwapBytesUint16(value.port)
	} else if pkt.IPv4.NextProtoID == common.UDPNumber {
		pkt.UDP.SrcPort = packet.SwapBytesUint16(value.port)
	} else {
		// Only address is not modified in ICMP packets
	}

	return true
}
