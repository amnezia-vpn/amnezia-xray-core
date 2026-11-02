package dispatcher

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func bittorrentSnifferContext() context.Context {
	return context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
}

func bittorrentHandshake() []byte {
	b := make([]byte, 68)
	b[0] = 19
	copy(b[1:20], "BitTorrent protocol")
	copy(b[48:68], "-qB4530-xk2f9amqbtt3")
	return b
}

func bittorrentUTP() []byte {
	b := make([]byte, 20)
	b[0] = 0x01
	binary.BigEndian.PutUint16(b[2:4], 0x07e1)
	binary.BigEndian.PutUint32(b[4:8], 1)
	return b
}

func bittorrentDHT() []byte {
	return []byte("d1:ad2:id20:abcdefghijklmnopqrst" + "e1:q9:get_peers1:t2:aa1:y1:qe")
}

func bittorrentTrackerConnect() []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[:8], 0x41727101980)
	binary.BigEndian.PutUint32(b[12:16], 0xdeadbeef)
	return b
}

func TestSniffBittorrentTrafficThroughFullChain(t *testing.T) {
	cases := []struct {
		name     string
		payload  []byte
		network  net.Network
		protocol string
	}{
		{"tcp handshake", bittorrentHandshake(), net.Network_TCP, "bittorrent"},
		{"utp", bittorrentUTP(), net.Network_UDP, "bittorrent"},
		{"dht", bittorrentDHT(), net.Network_UDP, "bittorrent"},
		{"udp tracker connect", bittorrentTrackerConnect(), net.Network_UDP, "bittorrent"},
		{"http tracker announce", []byte("GET /announce?port=6881 HTTP/1.1\r\nHost: tracker.example.com\r\n\r\n"), net.Network_TCP, "http"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := bittorrentSnifferContext()
			result, err := NewSniffer(ctx).Sniff(ctx, tc.payload, tc.network)
			if err != nil || result == nil {
				t.Fatalf("Sniff() = %v, %v; want %s", result, err, tc.protocol)
			}
			if got := result.Protocol(); !strings.HasPrefix(got, tc.protocol) {
				t.Fatalf("Protocol() = %q, want %q", got, tc.protocol)
			}
		})
	}
}
