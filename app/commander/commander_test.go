package commander

import (
	"context"
	"testing"
)

func TestNewCommanderRejectsNegativeMessageLimits(t *testing.T) {
	for _, config := range []*Config{
		{MaxReceiveMessageSize: -1},
		{MaxSendMessageSize: -1},
	} {
		if _, err := NewCommander(context.Background(), config); err == nil {
			t.Fatalf("negative gRPC message limit was accepted: %+v", config)
		}
	}
}
