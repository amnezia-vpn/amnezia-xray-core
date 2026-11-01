package outbound

import (
	"context"
	"errors"
	"math"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/filter"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/udp"
)

type maskedOutboundMarkRecorder struct {
	mark  uint32
	calls int
	err   error
}

func (r *maskedOutboundMarkRecorder) Dial(_ context.Context, _ net.Address, _ net.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	r.calls++
	r.mark = uint32(sockopt.GetMark())
	return nil, r.err
}

func (*maskedOutboundMarkRecorder) DestIpAddress() net.IP { return nil }

func TestHandlerDialPreservesUserFwmarkWithFinalMask(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("per-user socket marks are supported on Linux")
	}
	mask := serial.ToTypedMessage(&filter.Config{})
	base, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{
		SocketSettings: &internet.SocketConfig{Mark: 7},
		Tcpmasks:       []*serial.TypedMessage{mask},
		Udpmasks:       []*serial.TypedMessage{mask},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{streamSettings: base}
	sentinel := errors.New("stop before opening a socket")
	recorder := &maskedOutboundMarkRecorder{err: sentinel}
	internet.UseAlternativeSystemDialer(recorder)
	t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })

	tests := []struct {
		name string
		mark uint32
		want uint32
	}{
		{name: "unmarked", want: 7},
		{name: "per user", mark: 1_000_000_000, want: 1_000_000_000},
		{name: "full uint32", mark: math.MaxUint32, want: math.MaxUint32},
	}
	for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
		t.Run(network.String(), func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					ctx := session.ContextWithOutboundSocketMark(context.Background(), test.mark)
					recorder.calls = 0
					destination := net.Destination{Network: network, Address: net.LocalHostIP, Port: 443}
					_, err := h.Dial(ctx, destination)
					if !errors.Is(err, sentinel) {
						t.Fatalf("Dial error = %v, want sentinel", err)
					}
					if recorder.calls != 1 {
						t.Fatalf("system dial calls = %d, want 1", recorder.calls)
					}
					if recorder.mark != test.want {
						t.Errorf("socket mark = %d, want %d", recorder.mark, test.want)
					}
					if base.SocketSettings.Mark != 7 {
						t.Fatalf("shared socket mark = %d, want 7", base.SocketSettings.Mark)
					}
				})
			}
		})
	}
}
