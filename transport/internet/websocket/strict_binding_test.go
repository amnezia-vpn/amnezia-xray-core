package websocket_test

import (
	"context"
	goerrors "errors"
	"os"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	. "github.com/xtls/xray-core/transport/internet/websocket"
)

func TestDialRejectsStrictBindingBrowserDialer(t *testing.T) {
	setBrowserDialer(t, true)

	conn, err := Dial(
		context.Background(),
		net.TCPDestination(net.DomainAddress("example.com"), 443),
		&internet.MemoryStreamConfig{
			ProtocolName:     "websocket",
			ProtocolSettings: &Config{},
			SocketSettings: &internet.SocketConfig{
				Interface:     "test-interface",
				StrictBinding: true,
			},
		},
	)
	if conn != nil {
		conn.Close()
		t.Fatal("Dial() returned a connection through the browser dialer")
	}
	var configErr *internet.StrictBindingConfigError
	if !goerrors.As(err, &configErr) {
		t.Fatalf("Dial() error type = %T, want *internet.StrictBindingConfigError", err)
	}
	if configErr.Kind != internet.StrictBindingConfigBypass {
		t.Fatalf("Dial() error kind = %q, want %q", configErr.Kind, internet.StrictBindingConfigBypass)
	}
	if configErr.Bypass != "browser dialer" {
		t.Fatalf("Dial() bypass = %q, want browser dialer", configErr.Bypass)
	}
}

func TestDelayedDialRejectsBrowserDialerActivatedBeforeWrite(t *testing.T) {
	restoreBrowserDialer := preserveBrowserDialer(t)
	t.Cleanup(restoreBrowserDialer)
	setBrowserDialerState(t, false)

	conn, err := Dial(
		context.Background(),
		net.TCPDestination(net.DomainAddress("example.com"), 443),
		&internet.MemoryStreamConfig{
			ProtocolName: "websocket",
			ProtocolSettings: &Config{
				Ed: 1,
			},
			SocketSettings: &internet.SocketConfig{
				Interface:     "test-interface",
				StrictBinding: true,
			},
		},
	)
	if err != nil {
		t.Fatalf("Dial() before browser activation failed: %v", err)
	}
	defer conn.Close()

	setBrowserDialerState(t, true)
	n, err := conn.Write([]byte{1})
	if n != 0 {
		t.Fatalf("Write() wrote %d bytes through the browser dialer", n)
	}
	var configErr *internet.StrictBindingConfigError
	if !goerrors.As(err, &configErr) {
		t.Fatalf("Write() error type = %T, want wrapped *internet.StrictBindingConfigError", err)
	}
	if configErr.Kind != internet.StrictBindingConfigBypass {
		t.Fatalf("Write() error kind = %q, want %q", configErr.Kind, internet.StrictBindingConfigBypass)
	}
}

func setBrowserDialer(t *testing.T, enabled bool) {
	t.Helper()

	restore := preserveBrowserDialer(t)
	setBrowserDialerState(t, enabled)
	t.Cleanup(restore)
}

func preserveBrowserDialer(t *testing.T) func() {
	t.Helper()

	oldValue, hadOldValue := os.LookupEnv(platform.BrowserDialerAddress)
	return func() {
		if hadOldValue {
			_ = os.Setenv(platform.BrowserDialerAddress, oldValue)
		} else {
			_ = os.Unsetenv(platform.BrowserDialerAddress)
		}
		browser_dialer.Reload()
	}
}

func setBrowserDialerState(t *testing.T, enabled bool) {
	t.Helper()

	if enabled {
		if err := os.Setenv(platform.BrowserDialerAddress, "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Unsetenv(platform.BrowserDialerAddress); err != nil {
		t.Fatal(err)
	}
	browser_dialer.Reload()
}
