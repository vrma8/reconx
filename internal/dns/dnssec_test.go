package dns

import (
	"encoding/binary"
	"testing"
)

func TestDNSKeyQuerySetsDOBit(t *testing.T) {
	query, err := dnskeyQuery("example.test")
	if err != nil {
		t.Fatal(err)
	}
	if query[2]&1 != 1 || binary.BigEndian.Uint16(query[len(query)-10:len(query)-8]) != 41 {
		t.Fatalf("query = %x", query)
	}
	if binary.BigEndian.Uint16(query[len(query)-8:len(query)-6]) != 4096 {
		t.Fatalf("OPT class does not set DO bit: %x", query)
	}
}

func TestParseDNSSECResponse(t *testing.T) {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[2:4], 0x0020)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[6:8], 2)
	packet = append(packet, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 48, 0, 1)
	packet = append(packet, 0xc0, 0x0c, 0, 48, 0, 1, 0, 0, 0, 0, 0, 3, 1, 2, 3)
	packet = append(packet, 0xc0, 0x0c, 0, 46, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0)
	ad, keys, signatures, err := parseDNSSECResponse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !ad || keys != 1 || signatures != 1 {
		t.Fatalf("ad=%t keys=%d sigs=%d", ad, keys, signatures)
	}
}
