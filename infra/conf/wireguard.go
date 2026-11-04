package conf

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/proxy/wireguard"
	"google.golang.org/protobuf/proto"
)

type WireGuardPeerConfig struct {
	PublicKey    string          `json:"publicKey"`
	PreSharedKey string          `json:"preSharedKey"`
	Endpoint     string          `json:"endpoint"`
	KeepAlive    json.RawMessage `json:"keepAlive"`
	AllowedIPs   []string        `json:"allowedIPs,omitempty"`

	Level uint32 `json:"level"`
	Email string `json:"email"`
}

func (c *WireGuardPeerConfig) Build() (*wireguard.PeerConfig, error) {
	var err error
	config := new(wireguard.PeerConfig)

	if c.PublicKey != "" {
		config.PublicKey, err = ParseWireGuardKey(c.PublicKey)
		if err != nil {
			return nil, err
		}
	}

	if c.PreSharedKey != "" {
		config.PreSharedKey, err = ParseWireGuardKey(c.PreSharedKey)
		if err != nil {
			return nil, err
		}
	}

	config.Endpoint = c.Endpoint
	if len(c.KeepAlive) != 0 && string(c.KeepAlive) != "null" {
		config.KeepAlive, err = parseAmneziaRange(c.KeepAlive)
		if err != nil {
			return nil, errors.New("invalid WireGuard keepAlive").Base(err)
		}
	}
	if c.AllowedIPs == nil {
		config.AllowedIps = []string{"0.0.0.0/0", "::0/0"}
	} else {
		config.AllowedIps = c.AllowedIPs
	}

	return config, nil
}

type WireGuardConfig struct {
	IsClient bool `json:""`

	NoKernelTun            bool                   `json:"noKernelTun"`
	SecretKey              string                 `json:"secretKey"`
	Address                []string               `json:"address"`
	Peers                  []*WireGuardPeerConfig `json:"peers"`
	MTU                    int32                  `json:"mtu"`
	Reserved               []byte                 `json:"reserved"`
	DNS                    []string               `json:"remoteDNS"`
	Jc                     *uint32                `json:"jc,omitempty"`
	Jmin                   *uint32                `json:"jmin,omitempty"`
	Jmax                   *uint32                `json:"jmax,omitempty"`
	S1                     *uint16                `json:"s1,omitempty"`
	S2                     *uint16                `json:"s2,omitempty"`
	S3                     *uint16                `json:"s3,omitempty"`
	S4                     *uint16                `json:"s4,omitempty"`
	H1                     json.RawMessage        `json:"h1,omitempty"`
	H2                     json.RawMessage        `json:"h2,omitempty"`
	H3                     json.RawMessage        `json:"h3,omitempty"`
	H4                     json.RawMessage        `json:"h4,omitempty"`
	I1                     string                 `json:"i1,omitempty"`
	I2                     string                 `json:"i2,omitempty"`
	I3                     string                 `json:"i3,omitempty"`
	I4                     string                 `json:"i4,omitempty"`
	I5                     string                 `json:"i5,omitempty"`
	HeaderProtectionKey    string                 `json:"header_protection_key,omitempty"`
	ContentPaddingAddition json.RawMessage        `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         json.RawMessage        `json:"rekey_after_time,omitempty"`
	RekeyTimeout           json.RawMessage        `json:"rekey_timeout,omitempty"`
	RejectAfterTime        json.RawMessage        `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       json.RawMessage        `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   json.RawMessage        `json:"max_handshake_attempts,omitempty"`
	RandomTrailers         *bool                  `json:"random_trailers,omitempty"`
	DisableCookies         *bool                  `json:"disable_cookies,omitempty"`
}

func (c *WireGuardConfig) Build() (proto.Message, error) {
	config := new(wireguard.DeviceConfig)

	var err error
	config.SecretKey, err = ParseWireGuardKey(c.SecretKey)
	if err != nil {
		return nil, errors.New("invalid WireGuard secret key: %w", err)
	}

	if c.Address == nil {
		// bogon ips
		config.Endpoint = []string{"10.0.0.1", "fd59:7153:2388:b5fd:0000:0000:0000:0001"}
	} else {
		config.Endpoint = c.Address
	}

	if c.IsClient {
		config.Peers = make([]*wireguard.PeerConfig, len(c.Peers))
		for i, p := range c.Peers {
			msg, err := p.Build()
			if err != nil {
				return nil, err
			}
			config.Peers[i] = msg
		}
	} else {
		config.Users = make([]*protocol.User, len(c.Peers))
		processUser := func(idx int) error {
			p := c.Peers[idx]
			m, err := p.Build()
			if err != nil {
				return err
			}
			config.Users[idx] = &protocol.User{
				Email:   p.Email,
				Level:   p.Level,
				Account: serial.ToTypedMessage(m),
			}
			return nil
		}
		if err := task.ParallelForN(len(c.Peers), processUser); err != nil {
			return nil, err
		}
	}

	if c.MTU == 0 {
		config.Mtu = 1420
	} else {
		config.Mtu = c.MTU
	}

	if len(c.Reserved) != 0 && len(c.Reserved) != 3 {
		return nil, errors.New(`"reserved" should be empty or 3 bytes`)
	}
	config.Reserved = c.Reserved

	config.IsClient = c.IsClient
	config.NoKernelTun = c.NoKernelTun
	config.DNS = c.DNS
	config.AmneziaOptions, err = c.amneziaOptions()
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (c *WireGuardConfig) amneziaOptions() (map[string]string, error) {
	options := make(map[string]string)
	for name, value := range map[string]*uint32{"jc": c.Jc, "jmin": c.Jmin, "jmax": c.Jmax} {
		if value != nil {
			options[name] = strconv.FormatUint(uint64(*value), 10)
		}
	}
	for name, value := range map[string]*uint16{"s1": c.S1, "s2": c.S2, "s3": c.S3, "s4": c.S4} {
		if value != nil {
			options[name] = strconv.FormatUint(uint64(*value), 10)
		}
	}
	if c.Jmin != nil && c.Jmax != nil && *c.Jmin > *c.Jmax {
		return nil, errors.New("AmneziaWG jmin exceeds jmax")
	}
	for name, raw := range map[string]json.RawMessage{
		"h1": c.H1, "h2": c.H2, "h3": c.H3, "h4": c.H4,
		"content_padding_addition": c.ContentPaddingAddition,
		"rekey_after_time":         c.RekeyAfterTime, "rekey_timeout": c.RekeyTimeout,
		"reject_after_time": c.RejectAfterTime, "keepalive_timeout": c.KeepaliveTimeout,
		"max_handshake_attempts": c.MaxHandshakeAttempts,
	} {
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		value, err := parseAmneziaRange(raw)
		if err != nil {
			return nil, errors.New("invalid AmneziaWG ", name)
		}
		options[name] = value
	}
	for name, value := range map[string]*bool{"random_trailers": c.RandomTrailers, "disable_cookies": c.DisableCookies} {
		if value != nil {
			options[name] = strconv.FormatBool(*value)
		}
	}
	if c.HeaderProtectionKey != "" {
		key, err := ParseWireGuardKey(c.HeaderProtectionKey)
		if err != nil || len(key) != 64 {
			return nil, errors.New("invalid AmneziaWG header_protection_key: expected a 32-byte key")
		}
		if key != strings.Repeat("0", 64) {
			for _, padding := range []*uint16{c.S1, c.S2, c.S3, c.S4} {
				if padding == nil || *padding < awgdevice.HeaderCipherNonceSize {
					return nil, errors.New("AmneziaWG header protection requires s1-s4 >= 12")
				}
			}
		}
		options["header_protection_key"] = key
	}
	for name, value := range map[string]string{"i1": c.I1, "i2": c.I2, "i3": c.I3, "i4": c.I4, "i5": c.I5} {
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, errors.New("invalid AmneziaWG ", name)
		}
		if value != "" {
			options[name] = value
		}
	}
	return options, nil
}

func parseAmneziaRange(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		var number uint32
		if err := json.Unmarshal(raw, &number); err != nil {
			return "", err
		}
		value = strconv.FormatUint(uint64(number), 10)
	}
	var interval awgdevice.UintRange
	if err := interval.FromString(value); err != nil {
		return "", err
	}
	return interval.ToString(), nil
}

func ParseWireGuardKey(str string) (string, error) {
	var err error

	if str == "" {
		return "", errors.New("key must not be empty")
	}

	if len(str) == 64 {
		_, err = hex.DecodeString(str)
		if err == nil {
			return str, nil
		}
	}

	var dat []byte
	str = strings.TrimSuffix(str, "=")
	if strings.ContainsRune(str, '+') || strings.ContainsRune(str, '/') {
		dat, err = base64.RawStdEncoding.DecodeString(str)
	} else {
		dat, err = base64.RawURLEncoding.DecodeString(str)
	}
	if err == nil {
		if len(dat) != 32 {
			return "", errors.New("WireGuard key must contain exactly 32 bytes")
		}
		return hex.EncodeToString(dat), nil
	}

	return "", errors.New("failed to deserialize key").Base(err)
}
