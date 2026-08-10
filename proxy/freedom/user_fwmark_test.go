package freedom

import (
	"context"
	"math"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func TestContextWithVLESSUserFwmark(t *testing.T) {
	tests := []struct {
		name     string
		inbound  *session.Inbound
		wantMark uint32
	}{
		{name: "missing inbound"},
		{name: "missing user", inbound: &session.Inbound{Name: "vless"}},
		{name: "disabled", inbound: &session.Inbound{Name: "vless", User: &protocol.MemoryUser{Fwmark: 0}}},
		{name: "other protocol", inbound: &session.Inbound{Name: "vmess", User: &protocol.MemoryUser{Fwmark: 1_000_000_000}}},
		{name: "vless", inbound: &session.Inbound{Name: "vless", User: &protocol.MemoryUser{Fwmark: math.MaxUint32}}, wantMark: math.MaxUint32},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.inbound != nil {
				ctx = session.ContextWithInbound(ctx, test.inbound)
			}
			ctx = contextWithVLESSUserFwmark(ctx)
			if got := session.OutboundSocketMarkFromContext(ctx); got != test.wantMark {
				t.Fatalf("mark = %d, want %d", got, test.wantMark)
			}
		})
	}
}
