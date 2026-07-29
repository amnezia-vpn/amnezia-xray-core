package splithttp_test

import (
	"context"
	goerrors "errors"
	"os"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

func TestDialRejectsStrictBindingBrowserDialer(t *testing.T) {
	enableBrowserDialer(t)

	conn, err := Dial(
		context.Background(),
		net.TCPDestination(net.DomainAddress("example.com"), 443),
		&internet.MemoryStreamConfig{
			ProtocolName:     "splithttp",
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

func enableBrowserDialer(t *testing.T) {
	t.Helper()

	oldValue, hadOldValue := os.LookupEnv(platform.BrowserDialerAddress)
	if err := os.Setenv(platform.BrowserDialerAddress, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	browser_dialer.Reload()
	t.Cleanup(func() {
		if hadOldValue {
			_ = os.Setenv(platform.BrowserDialerAddress, oldValue)
		} else {
			_ = os.Unsetenv(platform.BrowserDialerAddress)
		}
		browser_dialer.Reload()
	})
}
