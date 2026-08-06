package outbound

import (
	"context"
	stderrors "errors"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	xproxy "github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

type countingMuxWorkerFactory struct {
	calls atomic.Int32
}

func (f *countingMuxWorkerFactory) Create() (*mux.ClientWorker, error) {
	f.calls.Add(1)
	return nil, stderrors.New("unexpected mux worker creation")
}

type reusableMuxWorkerPicker struct {
	worker *mux.ClientWorker
	picks  atomic.Int32
}

func (p *reusableMuxWorkerPicker) PickAvailable() (*mux.ClientWorker, error) {
	p.picks.Add(1)
	return p.worker, nil
}

type outboundErrorTracker struct {
	err error
}

func (t *outboundErrorTracker) SubmitError(err error) {
	t.err = err
}

type plainTestOutbound struct{}

func (*plainTestOutbound) Process(context.Context, *transport.Link, internet.Dialer) error {
	return nil
}

type contextPreparingTestOutbound struct {
	processed bool
	mark      uint32
}

func (*contextPreparingTestOutbound) PrepareOutboundContext(ctx context.Context) context.Context {
	return session.ContextWithOutboundSocketMark(ctx, 1_000_000_000)
}

func (o *contextPreparingTestOutbound) Process(ctx context.Context, _ *transport.Link, _ internet.Dialer) error {
	o.processed = true
	o.mark = session.OutboundSocketMarkFromContext(ctx)
	return nil
}

func testOutboundContext(inboundName string, mark uint32, network net.Network) context.Context {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Name: inboundName,
		User: &protocol.MemoryUser{Fwmark: mark},
	})
	return session.ContextWithOutbounds(ctx, []*session.Outbound{{
		Target: net.Destination{
			Network: network,
			Address: net.DomainAddress("example.com"),
			Port:    80,
		},
	}})
}

func testOutboundLink(t *testing.T) *transport.Link {
	t.Helper()
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	t.Cleanup(func() {
		common.Interrupt(reader)
		common.Interrupt(writer)
	})
	return &transport.Link{Reader: reader, Writer: writer}
}

func requireStrictBindingMuxRejection(t *testing.T, err error, wantBypass string) {
	t.Helper()
	var configErr *internet.StrictBindingConfigError
	if !stderrors.As(err, &configErr) || configErr.Kind != internet.StrictBindingConfigBypass {
		t.Fatalf("error = %T %v, want strict-binding bypass", err, err)
	}
	if configErr.Bypass != wantBypass {
		t.Fatalf("bypass = %q, want %q", configErr.Bypass, wantBypass)
	}
}

func TestMarkedVLESSFreedomRejectsMuxBeforeWorkerCreation(t *testing.T) {
	factory := new(countingMuxWorkerFactory)
	h := &Handler{
		proxy: &freedom.Handler{},
		mux: &mux.ClientManager{
			Enabled: true,
			Picker:  &mux.IncrementalWorkerPicker{Factory: factory},
		},
	}
	tracker := new(outboundErrorTracker)
	ctx := session.TrackedConnectionError(testOutboundContext("vless", 1_000_000_000, net.Network_TCP), tracker)

	h.Dispatch(ctx, testOutboundLink(t))

	if got := factory.calls.Load(); got != 0 {
		t.Fatalf("mux worker creations = %d, want 0", got)
	}
	requireStrictBindingMuxRejection(t, tracker.err, "outbound mux")
}

func TestMarkedVLESSFreedomRejectsMuxBeforeReusableWorkerSelection(t *testing.T) {
	workerReader, workerWriter := pipe.New(pipe.WithoutSizeLimit())
	worker, err := mux.NewClientWorker(
		transport.Link{Reader: workerReader, Writer: workerWriter},
		mux.ClientStrategy{MaxConcurrency: 8},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		common.Must(worker.Close())
		common.Interrupt(workerReader)
		common.Interrupt(workerWriter)
	})
	picker := &reusableMuxWorkerPicker{worker: worker}
	h := &Handler{
		proxy: &freedom.Handler{},
		mux:   &mux.ClientManager{Enabled: true, Picker: picker},
	}
	tracker := new(outboundErrorTracker)
	ctx := session.TrackedConnectionError(testOutboundContext("vless", 1_000_000_000, net.Network_TCP), tracker)

	h.Dispatch(ctx, testOutboundLink(t))

	if got := picker.picks.Load(); got != 0 {
		t.Fatalf("reusable mux worker selections = %d, want 0", got)
	}
	requireStrictBindingMuxRejection(t, tracker.err, "outbound mux")
}

func TestMarkedVLESSFreedomRejectsXUDPBeforeWorkerCreation(t *testing.T) {
	factory := new(countingMuxWorkerFactory)
	h := &Handler{
		proxy: &freedom.Handler{},
		mux:   &mux.ClientManager{Enabled: true},
		xudp: &mux.ClientManager{
			Enabled: true,
			Picker:  &mux.IncrementalWorkerPicker{Factory: factory},
		},
	}
	tracker := new(outboundErrorTracker)
	ctx := session.TrackedConnectionError(testOutboundContext("vless", 1_000_000_000, net.Network_UDP), tracker)

	h.Dispatch(ctx, testOutboundLink(t))

	if got := factory.calls.Load(); got != 0 {
		t.Fatalf("XUDP worker creations = %d, want 0", got)
	}
	requireStrictBindingMuxRejection(t, tracker.err, "outbound XUDP")
}

func TestFreedomMuxFallbackFlowsRemainSelectable(t *testing.T) {
	tests := []struct {
		name        string
		proxy       xproxy.Outbound
		inboundName string
		mark        uint32
		settings    *internet.MemoryStreamConfig
	}{
		{
			name:        "zero user mark keeps static mark fallback",
			proxy:       &freedom.Handler{},
			inboundName: "vless",
			settings: &internet.MemoryStreamConfig{
				SocketSettings: &internet.SocketConfig{Mark: 7},
			},
		},
		{
			name:        "non VLESS inbound",
			proxy:       &freedom.Handler{},
			inboundName: "vmess",
			mark:        1_000_000_000,
		},
		{
			name:        "non freedom outbound",
			proxy:       &plainTestOutbound{},
			inboundName: "vless",
			mark:        1_000_000_000,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory := new(countingMuxWorkerFactory)
			h := &Handler{
				proxy:          test.proxy,
				streamSettings: test.settings,
				mux: &mux.ClientManager{
					Enabled: true,
					Picker:  &mux.IncrementalWorkerPicker{Factory: factory},
				},
			}
			ctx := testOutboundContext(test.inboundName, test.mark, net.Network_TCP)

			h.Dispatch(ctx, testOutboundLink(t))

			if got := factory.calls.Load(); got != 1 {
				t.Fatalf("mux worker creations = %d, want 1", got)
			}
		})
	}
}

func TestPreparedUserMarkContinuesThroughDirectOutbound(t *testing.T) {
	proxy := new(contextPreparingTestOutbound)
	h := &Handler{proxy: proxy}

	h.Dispatch(testOutboundContext("vless", 1_000_000_000, net.Network_TCP), testOutboundLink(t))

	if !proxy.processed {
		t.Fatal("direct outbound was not processed")
	}
	if proxy.mark != 1_000_000_000 {
		t.Fatalf("direct outbound mark = %d, want %d", proxy.mark, 1_000_000_000)
	}
}
