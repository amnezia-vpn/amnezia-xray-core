package internet

import (
	"context"
	goerrors "errors"
	"fmt"
	stdnet "net"
	"runtime"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestValidateStrictBindingForPlatform(t *testing.T) {
	tests := []struct {
		name       string
		platform   string
		config     *SocketConfig
		wantKind   StrictBindingConfigErrorKind
		wantOption SocketBindingOption
	}{
		{
			name:     "disabled remains backward compatible",
			platform: "netbsd",
			config: &SocketConfig{
				Mark:        1,
				DialerProxy: "proxy",
			},
		},
		{
			name:     "binding option is required",
			platform: "linux",
			config:   &SocketConfig{StrictBinding: true},
			wantKind: StrictBindingConfigMissingOption,
		},
		{
			name:     "linux mark",
			platform: "linux",
			config:   &SocketConfig{StrictBinding: true, Mark: 1},
		},
		{
			name:     "linux interface",
			platform: "linux",
			config:   &SocketConfig{StrictBinding: true, Interface: "eth0"},
		},
		{
			name:     "android mark and interface",
			platform: "android",
			config:   &SocketConfig{StrictBinding: true, Mark: 1, Interface: "wlan0"},
		},
		{
			name:     "darwin interface",
			platform: "darwin",
			config:   &SocketConfig{StrictBinding: true, Interface: "en0"},
		},
		{
			name:       "darwin mark is unsupported",
			platform:   "darwin",
			config:     &SocketConfig{StrictBinding: true, Mark: 1},
			wantKind:   StrictBindingConfigUnsupportedOption,
			wantOption: SocketBindingOptionMark,
		},
		{
			name:     "freebsd mark",
			platform: "freebsd",
			config:   &SocketConfig{StrictBinding: true, Mark: 1},
		},
		{
			name:       "freebsd interface is unsupported",
			platform:   "freebsd",
			config:     &SocketConfig{StrictBinding: true, Interface: "em0"},
			wantKind:   StrictBindingConfigUnsupportedOption,
			wantOption: SocketBindingOptionInterface,
		},
		{
			name:     "windows interface",
			platform: "windows",
			config:   &SocketConfig{StrictBinding: true, Interface: "Ethernet"},
		},
		{
			name:       "windows mark is unsupported",
			platform:   "windows",
			config:     &SocketConfig{StrictBinding: true, Mark: 1},
			wantKind:   StrictBindingConfigUnsupportedOption,
			wantOption: SocketBindingOptionMark,
		},
		{
			name:       "unsupported platform",
			platform:   "netbsd",
			config:     &SocketConfig{StrictBinding: true, Interface: "vio0"},
			wantKind:   StrictBindingConfigUnsupportedOption,
			wantOption: SocketBindingOptionInterface,
		},
		{
			name:     "dialer proxy bypass",
			platform: "linux",
			config: &SocketConfig{
				StrictBinding: true,
				Mark:          1,
				DialerProxy:   "proxy",
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "linux custom option cannot replace mark",
			platform: "linux",
			config: &SocketConfig{
				StrictBinding: true,
				Mark:          100,
				CustomSockopt: []*CustomSockopt{{
					Level: "1",
					Opt:   "36",
					Value: "200",
					Type:  "int",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "linux custom option cannot replace interface",
			platform: "linux",
			config: &SocketConfig{
				StrictBinding: true,
				Interface:     "eth0",
				CustomSockopt: []*CustomSockopt{{
					Level: "1",
					Opt:   "25",
					Value: "eth1",
					Type:  "str",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "linux custom option cannot replace interface by index",
			platform: "linux",
			config: &SocketConfig{
				StrictBinding: true,
				Mark:          100,
				CustomSockopt: []*CustomSockopt{{
					Level: "1",
					Opt:   "62",
					Value: "2",
					Type:  "int",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "linux custom option cannot replace ipv4 unicast interface",
			platform: "linux",
			config: &SocketConfig{
				StrictBinding: true,
				Interface:     "eth0",
				CustomSockopt: []*CustomSockopt{{
					Level: "0",
					Opt:   "50",
					Value: "2",
					Type:  "int",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "linux custom option cannot replace ipv6 unicast interface",
			platform: "linux",
			config: &SocketConfig{
				StrictBinding: true,
				Interface:     "eth0",
				CustomSockopt: []*CustomSockopt{{
					Level: "41",
					Opt:   "76",
					Value: "2",
					Type:  "int",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "linux custom option cannot replace multicast interface",
			platform: "linux",
			config: &SocketConfig{
				StrictBinding: true,
				Interface:     "eth0",
				CustomSockopt: []*CustomSockopt{{
					Level: "0",
					Opt:   "32",
					Value: "2",
					Type:  "int",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "darwin custom option cannot replace ipv4 interface",
			platform: "darwin",
			config: &SocketConfig{
				StrictBinding: true,
				Interface:     "en0",
				CustomSockopt: []*CustomSockopt{{
					Level: "0",
					Opt:   "25",
					Value: "2",
					Type:  "int",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "darwin custom option cannot replace ipv6 interface",
			platform: "darwin",
			config: &SocketConfig{
				StrictBinding: true,
				Interface:     "en0",
				CustomSockopt: []*CustomSockopt{{
					Level: "41",
					Opt:   "125",
					Value: "2",
					Type:  "int",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "darwin custom option cannot replace multicast interface",
			platform: "darwin",
			config: &SocketConfig{
				StrictBinding: true,
				Interface:     "en0",
				CustomSockopt: []*CustomSockopt{{
					Level: "0",
					Opt:   "66",
					Value: "2",
					Type:  "int",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "windows custom option cannot replace interface",
			platform: "windows",
			config: &SocketConfig{
				StrictBinding: true,
				Interface:     "Ethernet",
				CustomSockopt: []*CustomSockopt{{
					Level: "0",
					Opt:   "31",
					Value: "2",
					Type:  "int",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "windows custom option cannot replace multicast interface",
			platform: "windows",
			config: &SocketConfig{
				StrictBinding: true,
				Interface:     "Ethernet",
				CustomSockopt: []*CustomSockopt{{
					Level: "41",
					Opt:   "9",
					Value: "2",
					Type:  "int",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "non-conflicting custom option remains supported",
			platform: "linux",
			config: &SocketConfig{
				StrictBinding: true,
				Mark:          100,
				CustomSockopt: []*CustomSockopt{{
					Level: "6",
					Opt:   "1",
					Value: "1",
					Type:  "int",
				}},
			},
		},
		{
			name:     "custom option for another system cannot conflict",
			platform: "linux",
			config: &SocketConfig{
				StrictBinding: true,
				Mark:          100,
				CustomSockopt: []*CustomSockopt{{
					System: "darwin",
					Level:  "1",
					Opt:    "36",
					Value:  "200",
					Type:   "int",
				}},
			},
		},
		{
			name:     "freebsd ignores unsupported custom socket options",
			platform: "freebsd",
			config: &SocketConfig{
				StrictBinding: true,
				Mark:          100,
				CustomSockopt: []*CustomSockopt{{
					Level: "1",
					Opt:   "36",
					Value: "200",
					Type:  "int",
				}},
			},
		},
		{
			name:     "freebsd custom option cannot replace user cookie",
			platform: "freebsd",
			config: &SocketConfig{
				StrictBinding: true,
				Mark:          100,
				CustomSockopt: []*CustomSockopt{{
					Level: "65535",
					Opt:   "4117",
					Value: "200",
					Type:  "int",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "freebsd custom option cannot select another fib",
			platform: "freebsd",
			config: &SocketConfig{
				StrictBinding: true,
				Mark:          100,
				CustomSockopt: []*CustomSockopt{{
					Level: "65535",
					Opt:   "4116",
					Value: "2",
					Type:  "int",
				}},
			},
			wantKind: StrictBindingConfigBypass,
		},
		{
			name:     "nil custom option is rejected",
			platform: "linux",
			config: &SocketConfig{
				StrictBinding: true,
				Mark:          100,
				CustomSockopt: []*CustomSockopt{nil},
			},
			wantKind: StrictBindingConfigBypass,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateStrictBindingForPlatform(test.config, test.platform)
			if test.wantKind == "" {
				if err != nil {
					t.Fatalf("validateStrictBindingForPlatform() error = %v", err)
				}
				return
			}

			var configErr *StrictBindingConfigError
			if !goerrors.As(err, &configErr) {
				t.Fatalf("validateStrictBindingForPlatform() error type = %T, want *StrictBindingConfigError", err)
			}
			if configErr.Kind != test.wantKind {
				t.Errorf("error kind = %q, want %q", configErr.Kind, test.wantKind)
			}
			if configErr.Option != test.wantOption {
				t.Errorf("error option = %q, want %q", configErr.Option, test.wantOption)
			}
		})
	}
}

func TestValidateStrictBindingDialPath(t *testing.T) {
	config := strictBindingConfigForCurrentPlatform(t)

	if err := validateStrictBindingDialPath(config, true); err != nil {
		t.Fatalf("default system dialer rejected: %v", err)
	}

	err := validateStrictBindingDialPath(config, false)
	var configErr *StrictBindingConfigError
	if !goerrors.As(err, &configErr) {
		t.Fatalf("alternative dialer error type = %T, want *StrictBindingConfigError", err)
	}
	if configErr.Kind != StrictBindingConfigSystemDialer {
		t.Fatalf("alternative dialer error kind = %q, want %q", configErr.Kind, StrictBindingConfigSystemDialer)
	}
}

func TestToMemoryStreamConfigRejectsInvalidStrictBinding(t *testing.T) {
	_, err := ToMemoryStreamConfig(&StreamConfig{
		SocketSettings: &SocketConfig{StrictBinding: true},
	})
	var configErr *StrictBindingConfigError
	if !goerrors.As(err, &configErr) {
		t.Fatalf("ToMemoryStreamConfig() error type = %T, want *StrictBindingConfigError", err)
	}
	if configErr.Kind != StrictBindingConfigMissingOption {
		t.Fatalf("strict binding error kind = %q, want %q", configErr.Kind, StrictBindingConfigMissingOption)
	}
}

func strictBindingConfigForCurrentPlatform(t *testing.T) *SocketConfig {
	t.Helper()

	config := &SocketConfig{StrictBinding: true}
	if mark, iface := strictBindingSupport(runtime.GOOS); mark {
		config.Mark = 1
	} else if iface {
		config.Interface = "test-interface"
	} else {
		t.Skipf("strict binding is unsupported on %s", runtime.GOOS)
	}
	return config
}

func TestDialSystemRejectsStrictBindingDialerProxy(t *testing.T) {
	config := strictBindingConfigForCurrentPlatform(t)
	config.DialerProxy = "proxy"

	conn, err := DialSystem(
		context.Background(),
		xnet.TCPDestination(xnet.LocalHostIP, 1),
		config,
	)
	if conn != nil {
		conn.Close()
		t.Fatal("DialSystem() returned a connection through a strict binding bypass")
	}
	var configErr *StrictBindingConfigError
	if !goerrors.As(err, &configErr) {
		t.Fatalf("DialSystem() error type = %T, want *StrictBindingConfigError", err)
	}
	if configErr.Kind != StrictBindingConfigBypass {
		t.Fatalf("DialSystem() error kind = %q, want %q", configErr.Kind, StrictBindingConfigBypass)
	}
}

func TestStrictBindingSocketOptionError(t *testing.T) {
	bindingErr := newSocketBindingError(
		SocketBindingOptionInterface,
		"test operation",
		"tcp4",
		"127.0.0.1:443",
		goerrors.New("test failure"),
	)
	wrappedBindingErr := fmt.Errorf("wrapped: %w", bindingErr)
	bestEffortErr := goerrors.New("best-effort option failed")

	tests := []struct {
		name   string
		config *SocketConfig
		err    error
		want   error
	}{
		{name: "nil error", config: &SocketConfig{StrictBinding: true}},
		{name: "strict binding failure", config: &SocketConfig{StrictBinding: true}, err: bindingErr, want: bindingErr},
		{name: "wrapped strict binding failure", config: &SocketConfig{StrictBinding: true}, err: wrappedBindingErr, want: wrappedBindingErr},
		{name: "best effort failure under strict mode", config: &SocketConfig{StrictBinding: true}, err: bestEffortErr},
		{name: "binding failure under compatibility mode", config: &SocketConfig{}, err: bindingErr},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := strictBindingSocketOptionError(test.config, test.err)
			if got != test.want {
				t.Fatalf("strictBindingSocketOptionError() = %v, want %v", got, test.want)
			}
		})
	}
}

type failingRawConn struct {
	err error
}

func (c failingRawConn) Control(func(uintptr)) error {
	return c.err
}

func (c failingRawConn) Read(func(uintptr) bool) error {
	return c.err
}

func (c failingRawConn) Write(func(uintptr) bool) error {
	return c.err
}

func TestApplyOutboundSocketOptionsWithPolicyControlFailure(t *testing.T) {
	controlErr := goerrors.New("raw control failed")

	err := applyOutboundSocketOptionsWithPolicy(
		context.Background(),
		"tcp4",
		"127.0.0.1:443",
		failingRawConn{err: controlErr},
		&SocketConfig{Mark: 1, StrictBinding: true},
	)
	var bindingErr *SocketBindingError
	if !goerrors.As(err, &bindingErr) {
		t.Fatalf("strict control error type = %T, want *SocketBindingError", err)
	}
	if bindingErr.Option != SocketBindingOptionMark {
		t.Fatalf("strict control binding option = %q, want %q", bindingErr.Option, SocketBindingOptionMark)
	}
	if !goerrors.Is(err, controlErr) {
		t.Fatalf("strict control error does not unwrap to %v: %v", controlErr, err)
	}

	err = applyOutboundSocketOptionsWithPolicy(
		context.Background(),
		"tcp4",
		"127.0.0.1:443",
		failingRawConn{err: controlErr},
		&SocketConfig{Mark: 1},
	)
	if !goerrors.Is(err, controlErr) {
		t.Fatalf("compatibility mode control error = %v, want %v", err, controlErr)
	}
}

func TestDefaultSystemDialerStrictBindingInterfaceFailure(t *testing.T) {
	_, supportsInterface := strictBindingSupport(runtime.GOOS)
	if !supportsInterface {
		t.Skipf("strict interface binding is unsupported on %s", runtime.GOOS)
	}

	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	tcpAddress := listener.Addr().(*stdnet.TCPAddr)
	tcpDestination := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(tcpAddress.Port))
	udpDestination := xnet.UDPDestination(xnet.LocalHostIP, 9)
	const missingInterface = "xray-strict-binding-interface-does-not-exist"

	dialer := &DefaultSystemDialer{}
	for _, test := range []struct {
		name        string
		destination xnet.Destination
	}{
		{name: "tcp", destination: tcpDestination},
		{name: "udp", destination: udpDestination},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, err := dialer.Dial(context.Background(), nil, test.destination, &SocketConfig{
				Interface:     missingInterface,
				StrictBinding: true,
			})
			if conn != nil {
				conn.Close()
				t.Fatal("strict dial unexpectedly returned a connection")
			}
			var bindingErr *SocketBindingError
			if !goerrors.As(err, &bindingErr) {
				t.Fatalf("strict dial error type = %T, want *SocketBindingError: %v", err, err)
			}
			if bindingErr.Option != SocketBindingOptionInterface {
				t.Fatalf("strict dial binding option = %q, want %q", bindingErr.Option, SocketBindingOptionInterface)
			}
		})
	}
}

func TestDefaultSystemDialerBestEffortInterfaceFailure(t *testing.T) {
	_, supportsInterface := strictBindingSupport(runtime.GOOS)
	if !supportsInterface {
		t.Skipf("interface binding is unsupported on %s", runtime.GOOS)
	}

	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	tcpAddress := listener.Addr().(*stdnet.TCPAddr)
	tcpDestination := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(tcpAddress.Port))
	udpDestination := xnet.UDPDestination(xnet.LocalHostIP, 9)
	const missingInterface = "xray-best-effort-interface-does-not-exist"

	dialer := &DefaultSystemDialer{}
	for _, test := range []struct {
		name        string
		destination xnet.Destination
	}{
		{name: "tcp", destination: tcpDestination},
		{name: "udp", destination: udpDestination},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, err := dialer.Dial(context.Background(), nil, test.destination, &SocketConfig{
				Interface: missingInterface,
			})
			if err != nil {
				t.Fatalf("best-effort dial failed: %v", err)
			}
			if conn == nil {
				t.Fatal("best-effort dial returned a nil connection")
			}
			conn.Close()
		})
	}
}
