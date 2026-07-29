package conf

import (
	goerrors "errors"
	"testing"

	"github.com/xtls/xray-core/transport/internet"
)

func TestOutboundDetourStrictBindingRejectsProxySettings(t *testing.T) {
	for _, transportLayerProxy := range []bool{false, true} {
		name := "application layer"
		if transportLayerProxy {
			name = "transport layer"
		}
		t.Run(name, func(t *testing.T) {
			config := &OutboundDetourConfig{
				StreamSetting: &StreamConfig{
					SocketSettings: &SocketConfig{
						Mark:          1,
						StrictBinding: true,
					},
				},
				ProxySettings: &ProxyConfig{
					Tag:                 "proxy",
					TransportLayerProxy: transportLayerProxy,
				},
			}

			err := config.checkChainProxyConfig()
			var configErr *internet.StrictBindingConfigError
			if !goerrors.As(err, &configErr) {
				t.Fatalf("checkChainProxyConfig() error type = %T, want *internet.StrictBindingConfigError", err)
			}
			if configErr.Kind != internet.StrictBindingConfigBypass {
				t.Fatalf("checkChainProxyConfig() error kind = %q, want %q", configErr.Kind, internet.StrictBindingConfigBypass)
			}
		})
	}
}

func TestOutboundDetourProxySettingsRemainCompatibleWithoutStrictBinding(t *testing.T) {
	config := &OutboundDetourConfig{
		StreamSetting: &StreamConfig{
			SocketSettings: &SocketConfig{
				Mark: 1,
			},
		},
		ProxySettings: &ProxyConfig{
			Tag: "proxy",
		},
	}

	if err := config.checkChainProxyConfig(); err != nil {
		t.Fatalf("checkChainProxyConfig() failed: %v", err)
	}
}
