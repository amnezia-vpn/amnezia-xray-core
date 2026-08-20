package conf

import "testing"

func TestAPIConfigBuildsGRPCMessageLimits(t *testing.T) {
	const (
		maxReceive = int32(16 * 1024 * 1024)
		maxSend    = int32(8 * 1024 * 1024)
	)
	config, err := (&APIConfig{
		Tag:                   "api",
		MaxReceiveMessageSize: maxReceive,
		MaxSendMessageSize:    maxSend,
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if config.GetMaxReceiveMessageSize() != maxReceive {
		t.Fatalf("max receive size = %d, want %d", config.GetMaxReceiveMessageSize(), maxReceive)
	}
	if config.GetMaxSendMessageSize() != maxSend {
		t.Fatalf("max send size = %d, want %d", config.GetMaxSendMessageSize(), maxSend)
	}
}

func TestAPIConfigRejectsNegativeGRPCMessageLimits(t *testing.T) {
	for _, config := range []*APIConfig{
		{Tag: "api", MaxReceiveMessageSize: -1},
		{Tag: "api", MaxSendMessageSize: -1},
	} {
		if _, err := config.Build(); err == nil {
			t.Fatalf("negative gRPC message limit was accepted: %+v", config)
		}
	}
}
