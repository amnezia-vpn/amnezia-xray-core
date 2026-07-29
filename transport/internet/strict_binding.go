package internet

import (
	"fmt"
	"runtime"
	"strconv"
)

// SocketBindingOption identifies an outbound socket property that determines
// which system route can be used.
type SocketBindingOption string

const (
	SocketBindingOptionMark      SocketBindingOption = "mark"
	SocketBindingOptionInterface SocketBindingOption = "interface"
)

// SocketBindingError reports a failure to apply a route-critical outbound
// socket binding. Callers can use errors.As to distinguish it from failures of
// best-effort socket options such as TCP Fast Open or keepalive tuning.
type SocketBindingError struct {
	Option    SocketBindingOption
	Operation string
	Network   string
	Address   string
	Err       error
}

func (e *SocketBindingError) Error() string {
	target := e.Network
	if e.Address != "" {
		target += " " + e.Address
	}
	if e.Operation != "" {
		return fmt.Sprintf("failed to apply socket binding %s with %s to %s: %v", e.Option, e.Operation, target, e.Err)
	}
	return fmt.Sprintf("failed to apply socket binding %s to %s: %v", e.Option, target, e.Err)
}

func (e *SocketBindingError) Unwrap() error {
	return e.Err
}

func newSocketBindingError(option SocketBindingOption, operation, network, address string, err error) *SocketBindingError {
	return &SocketBindingError{
		Option:    option,
		Operation: operation,
		Network:   network,
		Address:   address,
		Err:       err,
	}
}

// StrictBindingConfigErrorKind identifies why strict socket binding cannot be
// guaranteed for a configuration.
type StrictBindingConfigErrorKind string

const (
	StrictBindingConfigMissingOption     StrictBindingConfigErrorKind = "missing_option"
	StrictBindingConfigUnsupportedOption StrictBindingConfigErrorKind = "unsupported_option"
	StrictBindingConfigBypass            StrictBindingConfigErrorKind = "bypass"
	StrictBindingConfigSystemDialer      StrictBindingConfigErrorKind = "system_dialer"
)

// StrictBindingConfigError reports a configuration or dial-path choice that
// would bypass strict socket binding.
type StrictBindingConfigError struct {
	Kind     StrictBindingConfigErrorKind
	Option   SocketBindingOption
	Platform string
	Bypass   string
}

func (e *StrictBindingConfigError) Error() string {
	switch e.Kind {
	case StrictBindingConfigMissingOption:
		return "strict socket binding requires a non-zero mark or an interface"
	case StrictBindingConfigUnsupportedOption:
		return fmt.Sprintf("strict socket binding option %s is unsupported on %s", e.Option, e.Platform)
	case StrictBindingConfigBypass:
		return fmt.Sprintf("strict socket binding cannot be guaranteed through %s", e.Bypass)
	case StrictBindingConfigSystemDialer:
		return "strict socket binding requires the default system dialer"
	default:
		return "invalid strict socket binding configuration"
	}
}

// NewStrictBindingBypassError returns a typed error for a dial path that does
// not create the physical socket configured by SocketConfig.
func NewStrictBindingBypassError(bypass string) *StrictBindingConfigError {
	return &StrictBindingConfigError{
		Kind:   StrictBindingConfigBypass,
		Bypass: bypass,
	}
}

// ValidateStrictBinding verifies that the current platform and direct dial
// path can apply every configured route-critical binding.
func ValidateStrictBinding(config *SocketConfig) error {
	return validateStrictBindingForPlatform(config, runtime.GOOS)
}

func validateStrictBindingDialPath(config *SocketConfig, defaultSystemDialer bool) error {
	if err := ValidateStrictBinding(config); err != nil {
		return err
	}
	if config != nil && config.StrictBinding && !defaultSystemDialer {
		return &StrictBindingConfigError{Kind: StrictBindingConfigSystemDialer}
	}
	return nil
}

func validateStrictBindingForPlatform(config *SocketConfig, platform string) error {
	if config == nil || !config.StrictBinding {
		return nil
	}
	if config.Mark == 0 && config.Interface == "" {
		return &StrictBindingConfigError{Kind: StrictBindingConfigMissingOption}
	}
	if config.DialerProxy != "" {
		return NewStrictBindingBypassError("sockopt.dialerProxy")
	}

	supportsMark, supportsInterface := strictBindingSupport(platform)
	if config.Mark != 0 && !supportsMark {
		return &StrictBindingConfigError{
			Kind:     StrictBindingConfigUnsupportedOption,
			Option:   SocketBindingOptionMark,
			Platform: platform,
		}
	}
	if config.Interface != "" && !supportsInterface {
		return &StrictBindingConfigError{
			Kind:     StrictBindingConfigUnsupportedOption,
			Option:   SocketBindingOptionInterface,
			Platform: platform,
		}
	}
	if conflict := strictBindingCustomSockoptConflict(config, platform); conflict != "" {
		return NewStrictBindingBypassError(conflict)
	}
	return nil
}

func strictBindingCustomSockoptConflict(config *SocketConfig, platform string) string {
	for _, custom := range config.CustomSockopt {
		if custom == nil {
			return "nil customSockopt"
		}
		if custom.System != "" && custom.System != platform {
			continue
		}

		level := 6 // CustomSockopt's existing default is IPPROTO_TCP.
		if custom.Level != "" {
			level, _ = strconv.Atoi(custom.Level)
		}
		if custom.Opt == "" {
			continue
		}
		opt, _ := strconv.Atoi(custom.Opt)

		if customSockoptOverridesMark(platform, level, opt) {
			return fmt.Sprintf("customSockopt level %d opt %d overrides mark", level, opt)
		}
		if customSockoptOverridesInterface(platform, level, opt) {
			return fmt.Sprintf("customSockopt level %d opt %d overrides interface", level, opt)
		}
	}
	return ""
}

func customSockoptOverridesMark(platform string, level, opt int) bool {
	switch platform {
	case "linux", "android":
		// SOL_SOCKET / SO_MARK.
		return level == 1 && opt == 36
	case "freebsd":
		// SOL_SOCKET / SO_USER_COOKIE.
		return level == 0xffff && opt == 0x1015
	default:
		return false
	}
}

func customSockoptOverridesInterface(platform string, level, opt int) bool {
	switch platform {
	case "linux", "android":
		// SOL_SOCKET / SO_BINDTODEVICE or SO_BINDTOIFINDEX.
		bindToIfIndex := 62
		if platform == "linux" && runtime.GOARCH == "sparc64" {
			bindToIfIndex = 65
		}
		if level == 1 && (opt == 25 || opt == bindToIfIndex) {
			return true
		}
		// IPPROTO_IP / IP_UNICAST_IF or IP_MULTICAST_IF.
		if level == 0 && (opt == 50 || opt == 32) {
			return true
		}
		// IPPROTO_IPV6 / IPV6_UNICAST_IF or IPV6_MULTICAST_IF.
		return level == 41 && (opt == 76 || opt == 17)
	case "darwin", "ios":
		// IPPROTO_IP / IP_BOUND_IF, IP_MULTICAST_IF, or
		// IP_MULTICAST_IFINDEX; IPPROTO_IPV6 / IPV6_BOUND_IF or
		// IPV6_MULTICAST_IF.
		return (level == 0 && (opt == 25 || opt == 9 || opt == 66)) ||
			(level == 41 && (opt == 125 || opt == 9))
	case "windows":
		// IPPROTO_IP/IPPROTO_IPV6 with the unicast or multicast interface
		// option. Multicast options are route-critical for multicast targets.
		return (level == 0 || level == 41) && (opt == 31 || opt == 9)
	case "freebsd":
		// SOL_SOCKET / SO_SETFIB selects a routing table independently of the
		// configured user cookie.
		return level == 0xffff && opt == 0x1014
	default:
		return false
	}
}

func strictBindingSupport(platform string) (mark, iface bool) {
	switch platform {
	case "linux", "android":
		return true, true
	case "darwin", "ios":
		return false, true
	case "freebsd":
		return true, false
	case "windows":
		return false, true
	default:
		return false, false
	}
}
