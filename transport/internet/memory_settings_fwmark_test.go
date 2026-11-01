package internet_test

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/filter"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/udp"
)

type maskSocketMarkRecorder struct {
	mark  uint32
	calls int
	err   error
}

func (r *maskSocketMarkRecorder) Dial(_ context.Context, _ net.Address, _ net.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	r.calls++
	r.mark = uint32(sockopt.GetMark())
	return nil, r.err
}

func (*maskSocketMarkRecorder) DestIpAddress() net.IP { return nil }

func TestFinalMaskDialUsesFlowSocketSettings(t *testing.T) {
	makeSettings := func() *internet.MemoryStreamConfig {
		t.Helper()
		mask := serial.ToTypedMessage(&filter.Config{})
		settings, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{
			SocketSettings: &internet.SocketConfig{Mark: 7},
			Tcpmasks:       []*serial.TypedMessage{mask},
			Udpmasks:       []*serial.TypedMessage{mask},
		})
		if err != nil {
			t.Fatal(err)
		}
		return settings
	}
	base := makeSettings()
	unrelated := makeSettings()
	sentinel := errors.New("stop before opening a socket")
	recorder := &maskSocketMarkRecorder{err: sentinel}
	internet.UseAlternativeSystemDialer(recorder)
	t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })

	tests := []struct {
		name            string
		mark            uint32
		contextSettings *internet.MemoryStreamConfig
		want            uint32
	}{
		{name: "no override", want: 7},
		{name: "per user", mark: 1_000_000_000, contextSettings: base, want: 1_000_000_000},
		{name: "full uint32", mark: math.MaxUint32, contextSettings: base, want: math.MaxUint32},
		{name: "unrelated mask", mark: 1_000_000_000, contextSettings: unrelated, want: 7},
	}
	for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
		t.Run(network.String(), func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					ctx := context.Background()
					if test.contextSettings != nil {
						flow := *test.contextSettings
						flow.SocketSettings = &internet.SocketConfig{Mark: int32(test.mark)}
						ctx = session.ContextWithStreamSettings(ctx, &flow)
					}
					recorder.calls = 0
					destination := net.Destination{Network: network, Address: net.LocalHostIP, Port: 443}
					_, err := internet.Dial(ctx, destination, base)
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
