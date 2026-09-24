package freedom

import (
	"context"

	"github.com/xtls/xray-core/common/session"
)

func contextWithVLESSUserFwmark(ctx context.Context) context.Context {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.Name != "vless" || inbound.User == nil || inbound.User.Fwmark == 0 {
		return ctx
	}
	return session.ContextWithOutboundSocketMark(ctx, inbound.User.Fwmark)
}

// PrepareOutboundContext attaches the authenticated VLESS user's mark before
// the outbound handler decides whether a shared mux can be used.
func (*Handler) PrepareOutboundContext(ctx context.Context) context.Context {
	return contextWithVLESSUserFwmark(ctx)
}
