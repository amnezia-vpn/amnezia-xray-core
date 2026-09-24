package outbound

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

func streamSettingsWithOutboundSocketMark(settings *internet.MemoryStreamConfig, mark uint32, goos string, network net.Network) (*internet.MemoryStreamConfig, bool) {
	if mark == 0 || goos != "linux" {
		return settings, false
	}
	if network == net.Network_TCP && settings != nil && settings.ProtocolName != "" && settings.ProtocolName != "tcp" {
		return settings, false
	}
	if settings == nil {
		settings = &internet.MemoryStreamConfig{ProtocolName: "tcp"}
	}

	cloned := *settings
	if settings.SocketSettings == nil {
		cloned.SocketSettings = new(internet.SocketConfig)
	} else {
		cloned.SocketSettings = proto.Clone(settings.SocketSettings).(*internet.SocketConfig)
	}
	// SocketConfig.Mark is int32 for compatibility, while SO_MARK consumes the
	// same low 32 bits. Preserve the full per-user uint32 value explicitly.
	cloned.SocketSettings.Mark = int32(mark)
	return &cloned, true
}

func shouldDispatchViaMux(mark uint32) bool {
	return mark == 0
}
