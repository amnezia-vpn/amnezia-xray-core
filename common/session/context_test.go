package session

import (
	"context"
	"math"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func TestOutboundSocketMarkContext(t *testing.T) {
	ctx := ContextWithOutboundSocketMark(context.Background(), math.MaxUint32)
	if got := OutboundSocketMarkFromContext(ctx); got != uint32(math.MaxUint32) {
		t.Fatalf("mark = %d, want %d", got, uint32(math.MaxUint32))
	}
	if got := OutboundSocketMarkFromContext(context.Background()); got != 0 {
		t.Fatalf("unset mark = %d, want 0", got)
	}
}

func TestSubContextFromMuxInboundPreservesUserFwmark(t *testing.T) {
	parent := ContextWithInbound(context.Background(), &Inbound{
		Name: "vless",
		User: &protocol.MemoryUser{Fwmark: 1_000_000_000},
	})

	child := SubContextFromMuxInbound(parent)
	if got := InboundFromContext(child).User.Fwmark; got != 1_000_000_000 {
		t.Fatalf("fwmark = %d, want %d", got, 1_000_000_000)
	}
}
