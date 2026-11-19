package scanner

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestBuildSYNPacketChecksums(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.10").As4()
	destination := netip.MustParseAddr("192.0.2.20").As4()
	packet := buildSYNPacket(source[:], destination, 443, 50000)
	if len(packet) != 40 || packet[0] != 0x45 || packet[9] != 6 {
		t.Fatalf("packet header = %x", packet)
	}
	if checksum(packet[:20]) != 0 {
		t.Fatal("IP checksum should validate")
	}
	if binary.BigEndian.Uint16(packet[2:4]) != 40 {
		t.Fatalf("total length = %d", binary.BigEndian.Uint16(packet[2:4]))
	}
	if packet[20+13]&0x12 != 0x02 {
		t.Fatalf("flags = %x", packet[20+13])
	}
	pseudo := make([]byte, 12+20)
	copy(pseudo[0:4], source[:])
	copy(pseudo[4:8], destination[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], 20)
	copy(pseudo[12:], packet[20:])
	if checksum(pseudo) != 0 {
		t.Fatal("TCP pseudo-header checksum should validate")
	}
}

func TestBuildICMPEchoChecksum(t *testing.T) {
	packet := buildICMPEcho(7)
	if packet[0] != 8 || binary.BigEndian.Uint16(packet[6:8]) != 7 {
		t.Fatalf("ICMP echo = %x", packet)
	}
	if checksum(packet) != 0 {
		t.Fatal("ICMP checksum should validate")
	}
}
