package wireguard

import (
	"encoding/hex"
	"net/netip"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

func writeAmneziaOptions(dst *strings.Builder, config *DeviceConfig) {
	for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "header_protection_key", "content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts", "random_trailers", "disable_cookies"} {
		if value, ok := config.AmneziaOptions[key]; ok {
			dst.WriteString(key + "=" + value + "\n")
		}
	}
}

func buildClientUAPI(config *DeviceConfig) string {
	var output strings.Builder
	output.WriteString("private_key=" + config.SecretKey + "\n")
	writeAmneziaOptions(&output, config)
	for _, peer := range config.Peers {
		output.WriteString("public_key=" + peer.PublicKey + "\n")
		if peer.PreSharedKey != "" {
			output.WriteString("preshared_key=" + peer.PreSharedKey + "\n")
		}
		output.WriteString("endpoint=" + peer.Endpoint + "\n")
		for _, ip := range peer.AllowedIps {
			output.WriteString("allowed_ip=" + ip + "\n")
		}
		if peer.KeepAlive != "" {
			output.WriteString("persistent_keepalive_interval=" + peer.KeepAlive + "\n")
		}
	}
	return output.String()
}

func (p *PeerConfig) AsAccount() (protocol.Account, error) {
	pub, err := ParseKey(p.PublicKey)
	if err != nil {
		return nil, err
	}

	allowedIPs := make([]netip.Prefix, 0, len(p.AllowedIps))
	for i := range p.AllowedIps {
		p, err := netip.ParsePrefix(p.AllowedIps[i])
		if err != nil {
			return nil, err
		}
		allowedIPs = append(allowedIPs, p)
	}

	return &MemoryAccount{
		Pub:          *pub,
		AllowedIPs:   allowedIPs,
		PreSharedKey: p.PreSharedKey,
		KeepAlive:    p.KeepAlive,
	}, nil
}

type MemoryAccount struct {
	Pub          [32]byte
	AllowedIPs   []netip.Prefix
	PreSharedKey string
	KeepAlive    string
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	if b, ok := other.(*MemoryAccount); ok {
		return a.Pub == b.Pub
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	allowedIPs := make([]string, 0, len(a.AllowedIPs))
	for i := range a.AllowedIPs {
		allowedIPs = append(allowedIPs, a.AllowedIPs[i].String())
	}

	return &PeerConfig{
		PublicKey:    hex.EncodeToString(a.Pub[:]),
		AllowedIps:   allowedIPs,
		PreSharedKey: a.PreSharedKey,
		KeepAlive:    a.KeepAlive,
	}
}
