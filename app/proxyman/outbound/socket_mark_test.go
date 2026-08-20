package outbound

import (
	"math"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func TestStreamSettingsWithOutboundSocketMarkIsCallScoped(t *testing.T) {
	baseSocket := &internet.SocketConfig{Mark: 7, TcpKeepAliveInterval: 11}
	base := &internet.MemoryStreamConfig{ProtocolName: "tcp", SocketSettings: baseSocket}

	got, applied := streamSettingsWithOutboundSocketMark(base, math.MaxUint32, "linux", net.Network_TCP)
	if !applied {
		t.Fatal("Linux direct mark was not applied")
	}
	if got == base || got.SocketSettings == baseSocket {
		t.Fatal("shared stream settings were reused")
	}
	if uint32(got.SocketSettings.Mark) != math.MaxUint32 {
		t.Fatalf("socket mark bits = %d, want %d", uint32(got.SocketSettings.Mark), uint32(math.MaxUint32))
	}
	if baseSocket.Mark != 7 {
		t.Fatalf("shared socket settings were mutated: %+v", baseSocket)
	}
}

func TestStreamSettingsWithOutboundSocketMarkCreatesDefaults(t *testing.T) {
	got, applied := streamSettingsWithOutboundSocketMark(nil, 1_000_000_000, "linux", net.Network_TCP)
	if !applied || got == nil || got.SocketSettings == nil {
		t.Fatalf("settings = %+v, applied = %v", got, applied)
	}
	if uint32(got.SocketSettings.Mark) != 1_000_000_000 {
		t.Fatalf("socket mark = %d, want %d", uint32(got.SocketSettings.Mark), uint32(1_000_000_000))
	}
}

func TestStreamSettingsWithOutboundSocketMarkIsBestEffortOutsideContract(t *testing.T) {
	tests := []struct {
		name     string
		settings *internet.MemoryStreamConfig
		goos     string
		network  net.Network
	}{
		{name: "disabled", settings: &internet.MemoryStreamConfig{ProtocolName: "tcp"}, goos: "linux", network: net.Network_TCP},
		{name: "non linux", settings: &internet.MemoryStreamConfig{ProtocolName: "tcp"}, goos: "darwin", network: net.Network_TCP},
		{name: "pooled transport", settings: &internet.MemoryStreamConfig{ProtocolName: "splithttp"}, goos: "linux", network: net.Network_TCP},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mark := uint32(1_000_000_000)
			if test.name == "disabled" {
				mark = 0
			}
			got, applied := streamSettingsWithOutboundSocketMark(test.settings, mark, test.goos, test.network)
			if applied {
				t.Fatal("mark unexpectedly applied")
			}
			if got != test.settings {
				t.Fatal("unsupported settings were cloned or changed")
			}
		})
	}
}

func TestStreamSettingsWithOutboundSocketMarkConcurrentClones(t *testing.T) {
	baseSocket := &internet.SocketConfig{Mark: 7}
	base := &internet.MemoryStreamConfig{ProtocolName: "tcp", SocketSettings: baseSocket}
	marks := []uint32{1_000_000_000, math.MaxUint32}

	var wg sync.WaitGroup
	for _, mark := range marks {
		wg.Add(1)
		go func(mark uint32) {
			defer wg.Done()
			got, applied := streamSettingsWithOutboundSocketMark(base, mark, "linux", net.Network_TCP)
			if !applied || uint32(got.SocketSettings.Mark) != mark {
				t.Errorf("mark = %d, applied = %v; want %d, true", uint32(got.SocketSettings.Mark), applied, mark)
			}
		}(mark)
	}
	wg.Wait()
	if baseSocket.Mark != 7 {
		t.Fatalf("shared socket settings were mutated: %+v", baseSocket)
	}
}

func TestStreamSettingsWithOutboundSocketMarkAllowsDirectUDP(t *testing.T) {
	base := &internet.MemoryStreamConfig{ProtocolName: "splithttp"}
	got, applied := streamSettingsWithOutboundSocketMark(base, 1_000_000_000, "linux", net.Network_UDP)
	if !applied || uint32(got.SocketSettings.Mark) != 1_000_000_000 {
		t.Fatalf("UDP mark = %d, applied = %v", uint32(got.SocketSettings.Mark), applied)
	}
	if got == base {
		t.Fatal("shared UDP settings were reused")
	}
}

func TestPerUserMarkBypassesSharedOutboundMux(t *testing.T) {
	if shouldDispatchViaMux(1_000_000_000) {
		t.Fatal("marked flow may not use a shared outbound mux")
	}
	if !shouldDispatchViaMux(0) {
		t.Fatal("unmarked flow should preserve configured mux behavior")
	}
}
