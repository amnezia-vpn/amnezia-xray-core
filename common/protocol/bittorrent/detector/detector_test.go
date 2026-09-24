package detector

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common"
)

func TestHeaderContract(t *testing.T) {
	header := &Header{}
	if got := header.Protocol(); got != "bittorrent" {
		t.Fatalf("Protocol() = %q, want bittorrent", got)
	}
	if got := header.Domain(); got != "" {
		t.Fatalf("Domain() = %q, want empty", got)
	}
}

func TestSniffTCPHandshakes(t *testing.T) {
	for _, peerID := range []string{"-qB4530-xk2f9amqbtt3", "-TR4050-abcdefghijkl", "-DE13F0-abcdefghijkl", "-UT3600-abcdefghijkl", "-AZ5700-abcdefghijkl", "M7-10-0--abcdefghijk", "01234567890123456789"} {
		t.Run(peerID, func(t *testing.T) {
			header, err := SniffTCP(peerHandshake(peerID))
			if err != nil || header == nil {
				t.Fatalf("SniffTCP() = %v, %v; want header", header, err)
			}
		})
	}
}

func TestSniffTCPPrefixAndRejections(t *testing.T) {
	prefix := append([]byte{19}, []byte("BitTorrent protocol")...)
	if header, err := SniffTCP(prefix); err != nil || header == nil {
		t.Fatalf("20-byte prefix = %v, %v; want header", header, err)
	}
	if _, err := SniffTCP(prefix[:10]); err != common.ErrNoClue {
		t.Fatalf("10-byte prefix error = %v, want ErrNoClue", err)
	}
	for _, payload := range [][]byte{
		[]byte("GET /announce HTTP/1.1\r\n\r\n"),
		{0x16, 0x03, 0x01, 0x00, 0x80, 0x01, 0x00, 0x00, 0x7c, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		[]byte("SSH-2.0-OpenSSH_9.6\r\n"),
		append([]byte{0, 0, 0, 40}, []byte("d1:md11:ut_metadatai1ee")...),
		append([]byte{19}, []byte("BitTorrent protocoX")...),
		append([]byte{18}, []byte("BitTorrent protocol")...),
	} {
		if header, err := SniffTCP(payload); header != nil || err == nil || errors.Is(err, common.ErrNoClue) {
			t.Fatalf("SniffTCP(%x) = %v, %v; want definitive non-match", payload, header, err)
		}
	}
}

func TestSniffUDPContinuesAfterNoClue(t *testing.T) {
	payload := make([]byte, 16)
	binary.BigEndian.PutUint64(payload[0:8], 0x41727101980)
	binary.BigEndian.PutUint32(payload[8:12], 0)
	binary.BigEndian.PutUint32(payload[12:16], 0xDEADBEEF)

	header, err := SniffUDP(payload)
	if err != nil || header == nil {
		t.Fatalf("16-byte tracker connect not detected: header=%v err=%v", header, err)
	}
}

func TestSniffUDPRejectsDNSUDPTrackerCollisions(t *testing.T) {
	cases := []struct {
		name       string
		payload    []byte
		wantLength int
	}{
		{"98-byte EDNS announce collision", dnsTrackerAnnounceCollision(0xBEEF), 98},
		{"aligned two-record EDNS scrape collision", dnsTrackerScrapeCollision(0xCAFE), 56},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.payload) != tc.wantLength {
				t.Fatalf("DNS collision length = %d, want %d", len(tc.payload), tc.wantLength)
			}
			header, err := SniffUDP(tc.payload)
			if header != nil || err == nil || errors.Is(err, common.ErrNoClue) {
				t.Fatalf("SniffUDP() = %v, %v; want definitive non-match", header, err)
			}
		})
	}
}

func TestSniffUDPErrorAggregation(t *testing.T) {
	if _, err := SniffUDP([]byte{'d'}); err != common.ErrNoClue {
		t.Fatalf("one-byte d error = %v, want ErrNoClue", err)
	}
	if _, err := SniffUDP(seededBytes(41, 96)); err == nil || errors.Is(err, common.ErrNoClue) {
		t.Fatalf("unrelated datagram error = %v, want definitive non-match", err)
	}
}
