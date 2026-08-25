package detector

import (
	"math"
	"testing"
	"time"
)

func TestSniffUTPRecognizesPackets(t *testing.T) {
	sack := utpExtension{id: 1, data: []byte{0x80, 0, 0, 1}}
	closeReason := utpExtension{id: 3, data: []byte{0, 0, 3, 0xec}}
	cases := []struct {
		name    string
		payload []byte
	}{
		{"syn", utpPacket(4, 0xc0a8, 1, nil, nil)},
		{"state", utpPacket(2, 0xc0a8, 1, nil, nil)},
		{"data", utpPacket(0, 0x07e1, 1, nil, seededBytes(1, 32))},
		{"data with sack", utpPacket(0, 0x07e1, 1, []utpExtension{sack}, seededBytes(2, 32))},
		{"state with sack", utpPacket(2, 0x07e1, 1, []utpExtension{sack}, nil)},
		{"state with close reason", utpPacket(2, 0x07e1, 1, []utpExtension{closeReason}, nil)},
		{"data with chained extensions", utpPacket(0, 0x07e1, 1, []utpExtension{sack, closeReason}, seededBytes(3, 32))},
		{"fin", utpPacket(1, 0x07e1, 1, nil, nil)},
		{"reset", utpPacket(3, 0x07e1, 1, nil, nil)},
		{"zero timestamp", utpPacket(0, 0x07e1, 0, nil, seededBytes(4, 32))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := sniffUTP(tc.payload); err != nil {
				t.Fatalf("sniffUTP() error = %v", err)
			}
		})
	}
}

func TestSniffUTPIgnoresTimestampClockBase(t *testing.T) {
	for _, timestamp := range []uint32{0, 1, 123456789, 0xdeadbeef, math.MaxUint32, uint32(time.Now().UnixMicro()), uint32(time.Now().UnixNano())} {
		t.Run("timestamp", func(t *testing.T) {
			if err := sniffUTP(utpPacket(0, 0x07e1, timestamp, nil, seededBytes(int64(timestamp), 16))); err != nil {
				t.Fatalf("timestamp %#x rejected: %v", timestamp, err)
			}
		})
	}
}

func TestSniffUTPRejectsOtherDatagrams(t *testing.T) {
	unknownExtension := utpPacket(0, 0x07e1, 1, nil, nil)
	unknownExtension[1] = 5
	typeFive := utpPacket(0, 0x07e1, 1, nil, nil)
	typeFive[0] = 0x51
	zeroConnectionID := utpPacket(0, 0, 1, nil, nil)
	cases := []struct {
		name    string
		payload []byte
	}{
		{"dht", dhtQuery("get_peers", "d2:id20:"+string(fixedNodeID[:])+"e")},
		{"tracker", udpTrackerConnect(1)},
		{"lsd", []byte("BT-SEARCH * HTTP/1.1\r\n\r\n")},
		{"dns", []byte{0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}},
		{"ntp", append([]byte{0x1b}, make([]byte, 47)...)},
		{"wireguard initiation", append([]byte{1, 0, 0, 0}, seededBytes(5, 120)...)},
		{"wireguard data", append([]byte{4, 0, 0, 0}, seededBytes(6, 120)...)},
		{"zero connection id", zeroConnectionID},
		{"unknown extension", unknownExtension},
		{"type five", typeFive},
		{"quic", append([]byte{0xc3, 0, 0, 0, 1, 8, 0, 0, 0x20, 0}, seededBytes(7, 32)...)},
		{"random", seededBytes(8, 96)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := sniffUTP(tc.payload); err == nil {
				t.Fatal("sniffUTP() matched foreign datagram")
			}
		})
	}
}
