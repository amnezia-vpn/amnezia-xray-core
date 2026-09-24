package session

import (
	"context"
	"math"
	"testing"
)

func TestOutboundSocketMarkContext(t *testing.T) {
	ctx := ContextWithOutboundSocketMark(context.Background(), math.MaxUint32)
	if got := OutboundSocketMarkFromContext(ctx); got != math.MaxUint32 {
		t.Fatalf("mark = %d, want %d", got, uint32(math.MaxUint32))
	}
	if got := OutboundSocketMarkFromContext(context.Background()); got != 0 {
		t.Fatalf("unset mark = %d, want 0", got)
	}
}
