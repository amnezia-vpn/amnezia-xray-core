package outbound

import (
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

func cloneMemoryStreamConfig(settings *internet.MemoryStreamConfig) *internet.MemoryStreamConfig {
	if settings == nil {
		return nil
	}
	cloned := *settings
	if settings.SocketSettings != nil {
		cloned.SocketSettings = proto.Clone(settings.SocketSettings).(*internet.SocketConfig)
	}
	cloned.DownloadSettings = cloneMemoryStreamConfig(settings.DownloadSettings)
	return &cloned
}

func streamSettingsWithOutboundSocketMark(settings *internet.MemoryStreamConfig, mark uint32) (*internet.MemoryStreamConfig, error) {
	if err := validateUserSocketMarkTransport(settings, mark); err != nil {
		return nil, err
	}
	if settings == nil {
		var err error
		settings, err = internet.ToMemoryStreamConfig(nil)
		if err != nil {
			return nil, err
		}
	}
	cloned := cloneMemoryStreamConfig(settings)
	if cloned.SocketSettings == nil {
		cloned.SocketSettings = new(internet.SocketConfig)
	}
	cloned.SocketSettings.Mark = mark
	cloned.SocketSettings.StrictBinding = true
	return cloned, nil
}

func validateUserSocketMarkTransport(settings *internet.MemoryStreamConfig, mark uint32) error {
	if mark == 0 || settings == nil {
		return nil
	}

	switch settings.ProtocolName {
	case "grpc", "hysteria", "splithttp":
		return internet.NewStrictBindingBypassError(settings.ProtocolName + " transport client pool")
	default:
		return nil
	}
}

func validateUserSocketMarkPlatform(platform string) error {
	if platform == "linux" {
		return nil
	}
	return &internet.StrictBindingConfigError{
		Kind:     internet.StrictBindingConfigUnsupportedOption,
		Option:   internet.SocketBindingOptionMark,
		Platform: platform,
	}
}
