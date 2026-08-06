package outbound

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

func TestStreamSettingsWithOutboundSocketMarkIsIsolated(t *testing.T) {
	baseSocket := &internet.SocketConfig{Mark: 7, TcpKeepAliveInterval: 11}
	downloadSocket := &internet.SocketConfig{Mark: 8, TcpKeepAliveIdle: 13}
	base := &internet.MemoryStreamConfig{
		ProtocolName:   "tcp",
		SocketSettings: baseSocket,
		DownloadSettings: &internet.MemoryStreamConfig{
			ProtocolName:   "tcp",
			SocketSettings: downloadSocket,
		},
	}

	got, err := streamSettingsWithOutboundSocketMark(base, math.MaxUint32)
	if err != nil {
		t.Fatal(err)
	}
	if got == base || got.SocketSettings == baseSocket || got.DownloadSettings == base.DownloadSettings {
		t.Fatal("stream settings were not deeply isolated")
	}
	if got.SocketSettings.Mark != uint32(math.MaxUint32) || !got.SocketSettings.StrictBinding {
		t.Fatalf("primary socket = %+v", got.SocketSettings)
	}
	if baseSocket.Mark != 7 || baseSocket.StrictBinding {
		t.Fatalf("base socket was mutated: %+v", baseSocket)
	}
	if downloadSocket.Mark != 8 || downloadSocket.StrictBinding {
		t.Fatalf("download socket was mutated: %+v", downloadSocket)
	}
}

func TestStreamSettingsWithOutboundSocketMarkNilSettings(t *testing.T) {
	got, err := streamSettingsWithOutboundSocketMark(nil, 1_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.SocketSettings == nil {
		t.Fatalf("settings = %+v, want socket settings", got)
	}
	if got.SocketSettings.Mark != 1_000_000_000 || !got.SocketSettings.StrictBinding {
		t.Fatalf("socket settings = %+v", got.SocketSettings)
	}
}

func TestStreamSettingsWithOutboundSocketMarkConcurrentClones(t *testing.T) {
	baseSocket := &internet.SocketConfig{Mark: 7, TcpKeepAliveInterval: 11}
	base := &internet.MemoryStreamConfig{ProtocolName: "tcp", SocketSettings: baseSocket}
	marks := []uint32{1_000_000_000, 1_000_000_001}

	var wg sync.WaitGroup
	errs := make(chan error, len(marks))
	for _, mark := range marks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := streamSettingsWithOutboundSocketMark(base, mark)
			if err != nil {
				errs <- err
				return
			}
			if got.SocketSettings.Mark != mark || !got.SocketSettings.StrictBinding {
				errs <- errors.New("clone did not preserve its call-scoped mark")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if baseSocket.Mark != 7 || baseSocket.StrictBinding {
		t.Fatalf("shared base socket was mutated: %+v", baseSocket)
	}
}

func TestHandlerDialRejectsUserMarkPooledTransport(t *testing.T) {
	ctx := session.ContextWithOutboundSocketMark(context.Background(), 1_000_000_000)
	dest := net.TCPDestination(net.DomainAddress("example.com"), 443)

	for _, protocol := range []string{"grpc", "hysteria", "splithttp"} {
		t.Run(protocol, func(t *testing.T) {
			h := &Handler{
				streamSettings: &internet.MemoryStreamConfig{ProtocolName: protocol},
			}

			conn, err := h.Dial(ctx, dest)
			if conn != nil {
				conn.Close()
				t.Fatal("Dial() returned a connection for a marked pooled transport")
			}
			var configErr *internet.StrictBindingConfigError
			if !errors.As(err, &configErr) || configErr.Kind != internet.StrictBindingConfigBypass {
				t.Fatalf("Dial() error = %T %v, want strict-binding bypass", err, err)
			}
		})
	}
}

func TestStreamSettingsWithOutboundSocketMarkRejectsSplitHTTPBeforeDownloadSettingsRead(t *testing.T) {
	base := &internet.MemoryStreamConfig{ProtocolName: "splithttp"}
	downloads := []*internet.MemoryStreamConfig{
		{ProtocolName: "tcp", SocketSettings: &internet.SocketConfig{Mark: 7}},
		{ProtocolName: "tcp", SocketSettings: &internet.SocketConfig{Mark: 8}},
	}

	stop := make(chan struct{})
	ready := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(ready)
		for {
			select {
			case <-stop:
				return
			default:
				base.DownloadSettings = downloads[0]
				base.DownloadSettings = downloads[1]
			}
		}
	}()
	<-ready
	defer func() {
		close(stop)
		wg.Wait()
	}()

	for range 1_000 {
		got, err := streamSettingsWithOutboundSocketMark(base, 1_000_000_000)
		if got != nil {
			t.Fatal("marked SplitHTTP settings were cloned instead of rejected")
		}
		var configErr *internet.StrictBindingConfigError
		if !errors.As(err, &configErr) || configErr.Kind != internet.StrictBindingConfigBypass {
			t.Fatalf("error = %T %v, want strict-binding bypass", err, err)
		}
	}
}

func TestStreamSettingsWithOutboundSocketMarkAllowsDirectTransports(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			baseSocket := &internet.SocketConfig{Mark: 7}
			base := &internet.MemoryStreamConfig{ProtocolName: protocol, SocketSettings: baseSocket}

			got, err := streamSettingsWithOutboundSocketMark(base, 1_000_000_000)
			if err != nil {
				t.Fatal(err)
			}
			if got == base || got.SocketSettings == baseSocket {
				t.Fatal("direct transport settings were not isolated")
			}
			if got.SocketSettings.Mark != 1_000_000_000 || !got.SocketSettings.StrictBinding {
				t.Fatalf("socket settings = %+v", got.SocketSettings)
			}
			if baseSocket.Mark != 7 || baseSocket.StrictBinding {
				t.Fatalf("base socket was mutated: %+v", baseSocket)
			}
		})
	}
}

func TestValidateUserSocketMarkTransportAllowsStaticMarkFallback(t *testing.T) {
	settings := &internet.MemoryStreamConfig{
		ProtocolName:   "splithttp",
		SocketSettings: &internet.SocketConfig{Mark: 7},
	}
	if err := validateUserSocketMarkTransport(settings, 0); err != nil {
		t.Fatalf("zero user mark rejected static settings: %v", err)
	}
}

func TestValidateUserSocketMarkPlatform(t *testing.T) {
	if err := validateUserSocketMarkPlatform("linux"); err != nil {
		t.Fatalf("linux validation failed: %v", err)
	}
	for _, platform := range []string{"android", "darwin", "freebsd", "windows"} {
		t.Run(platform, func(t *testing.T) {
			var configErr *internet.StrictBindingConfigError
			if err := validateUserSocketMarkPlatform(platform); !errors.As(err, &configErr) || configErr.Kind != internet.StrictBindingConfigUnsupportedOption {
				t.Fatalf("error = %T %v, want unsupported-option error", err, err)
			}
		})
	}
}
