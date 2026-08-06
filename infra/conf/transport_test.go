package conf_test

import (
	"encoding/json"
	goerrors "errors"
	"math"
	"runtime"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	finalmaskcustom "github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
	"google.golang.org/protobuf/proto"
)

func TestSocketConfig(t *testing.T) {
	createParser := func() func(string) (proto.Message, error) {
		return func(s string) (proto.Message, error) {
			config := new(SocketConfig)
			if err := json.Unmarshal([]byte(s), config); err != nil {
				return nil, err
			}
			return config.Build()
		}
	}

	// test "tcpFastOpen": true, queue length 256 is expected. other parameters are tested here too
	expectedOutput := &internet.SocketConfig{
		Mark:           1,
		Tfo:            256,
		DomainStrategy: internet.DomainStrategy_USE_IP,
		DialerProxy:    "tag",
		HappyEyeballs:  &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"mark": 1,
				"tcpFastOpen": true,
				"domainStrategy": "UseIP",
				"dialerProxy": "tag"
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != 256 {
		t.Fatalf("unexpected parsed TFO value, which should be 256")
	}

	// test "tcpFastOpen": false, disabled TFO is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           -1,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": false
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != 0 {
		t.Fatalf("unexpected parsed TFO value, which should be 0")
	}

	// test "tcpFastOpen": 65535, queue length 65535 is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           65535,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": 65535
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != 65535 {
		t.Fatalf("unexpected parsed TFO value, which should be 65535")
	}

	// test "tcpFastOpen": -65535, disable TFO is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           -65535,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": -65535
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != 0 {
		t.Fatalf("unexpected parsed TFO value, which should be 0")
	}

	// test "tcpFastOpen": 0, no operation is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           0,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": 0
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != -1 {
		t.Fatalf("unexpected parsed TFO value, which should be -1")
	}

	// test omit "tcpFastOpen", no operation is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           0,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input:  `{}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != -1 {
		t.Fatalf("unexpected parsed TFO value, which should be -1")
	}

	// test "tcpFastOpen": null, no operation is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           0,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": null
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != -1 {
		t.Fatalf("unexpected parsed TFO value, which should be -1")
	}

	t.Run("full unsigned mark", func(t *testing.T) {
		config := new(SocketConfig)
		if err := json.Unmarshal([]byte(`{"mark":4294967295}`), config); err != nil {
			t.Fatal(err)
		}
		built, err := config.Build()
		if err != nil {
			t.Fatal(err)
		}
		if built.Mark != uint32(math.MaxUint32) {
			t.Fatalf("mark = %d, want %d", built.Mark, uint32(math.MaxUint32))
		}
	})

	t.Run("negative mark rejected", func(t *testing.T) {
		config := new(SocketConfig)
		if err := json.Unmarshal([]byte(`{"mark":-1}`), config); err == nil {
			t.Fatal("negative mark unexpectedly accepted")
		}
	})
}

func TestSocketConfigStrictBinding(t *testing.T) {
	t.Run("requires binding option", func(t *testing.T) {
		_, err := (&SocketConfig{StrictBinding: true}).Build()
		var configErr *internet.StrictBindingConfigError
		if !goerrors.As(err, &configErr) {
			t.Fatalf("Build() error type = %T, want *internet.StrictBindingConfigError", err)
		}
		if configErr.Kind != internet.StrictBindingConfigMissingOption {
			t.Fatalf("Build() error kind = %q, want %q", configErr.Kind, internet.StrictBindingConfigMissingOption)
		}
	})

	t.Run("rejects dialer proxy", func(t *testing.T) {
		_, err := (&SocketConfig{
			Mark:          1,
			StrictBinding: true,
			DialerProxy:   "proxy",
		}).Build()
		var configErr *internet.StrictBindingConfigError
		if !goerrors.As(err, &configErr) {
			t.Fatalf("Build() error type = %T, want *internet.StrictBindingConfigError", err)
		}
		if configErr.Kind != internet.StrictBindingConfigBypass {
			t.Fatalf("Build() error kind = %q, want %q", configErr.Kind, internet.StrictBindingConfigBypass)
		}
	})

	t.Run("json mapping", func(t *testing.T) {
		input := `{"strictBinding":true,"interface":"test-interface"}`
		if runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "freebsd" {
			input = `{"strictBinding":true,"mark":1}`
		}

		config := new(SocketConfig)
		if err := json.Unmarshal([]byte(input), config); err != nil {
			t.Fatal(err)
		}
		built, err := config.Build()
		if runtime.GOOS != "linux" &&
			runtime.GOOS != "android" &&
			runtime.GOOS != "freebsd" &&
			runtime.GOOS != "darwin" &&
			runtime.GOOS != "ios" &&
			runtime.GOOS != "windows" {
			if err == nil {
				t.Fatalf("Build() succeeded on unsupported platform %s", runtime.GOOS)
			}
			return
		}
		if err != nil {
			t.Fatalf("Build() failed: %v", err)
		}
		if !built.StrictBinding {
			t.Fatal("Build() did not preserve strictBinding")
		}
	})

	t.Run("disabled remains backward compatible", func(t *testing.T) {
		built, err := (&SocketConfig{
			Mark:        1,
			DialerProxy: "proxy",
		}).Build()
		if err != nil {
			t.Fatalf("Build() failed: %v", err)
		}
		if built.StrictBinding {
			t.Fatal("Build() enabled strict binding by default")
		}
	})
}

func TestHeaderCustomUDPBuild(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(HeaderCustomUDP) })

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"client": [
					{
						"type": "hex",
						"packet": "aabb"
					},
					{
						"rand": 2,
						"capture": "seed",
						"randRange": "16-32"
					}
				],
				"server": [
					{
						"capture": "txid",
						"transform": {
							"op": "concat",
							"args": [
								{"reuse": "seed"},
								{"u64": 258},
								{"type": "hex", "bytes": "c0de"}
							]
						}
					},
					{
						"reuse": "txid"
					}
				],
				"mode": "standalone"
			}`,
			Parser: parser,
			Output: &finalmaskcustom.UDPStandaloneConfig{
				Client: []*finalmaskcustom.UDPItem{
					{
						RandMax: 255,
						Packet:  []byte{0xAA, 0xBB},
					},
					{
						Rand:    2,
						RandMin: 16,
						RandMax: 32,
						Save:    "seed",
					},
				},
				Server: []*finalmaskcustom.UDPItem{
					{
						RandMax: 255,
						Save:    "txid",
						Expr: &finalmaskcustom.Expr{
							Op: "concat",
							Args: []*finalmaskcustom.ExprArg{
								{
									Value: &finalmaskcustom.ExprArg_Var{
										Var: "seed",
									},
								},
								{
									Value: &finalmaskcustom.ExprArg_U64{
										U64: 258,
									},
								},
								{
									Value: &finalmaskcustom.ExprArg_Bytes{
										Bytes: []byte{0xC0, 0xDE},
									},
								},
							},
						},
					},
					{
						RandMax: 255,
						Var:     "txid",
					},
				},
			},
		},
	})
}

func TestHeaderCustomTCPBuildRejectsMixedItemKinds(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(HeaderCustomTCP) })

	_, err := parser(`{
		"clients": [[
			{
				"packet": [1, 2],
				"reuse": "txid"
			}
		]]
	}`)
	if err == nil || !strings.Contains(err.Error(), "exactly one item kind") {
		t.Fatalf("expected mixed item kind rejection, got %v", err)
	}
}

func TestHeaderCustomUDPBuildRejectsInvalidVariableNames(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(HeaderCustomUDP) })

	_, err := parser(`{
		"client": [
			{
				"capture": "bad-name",
				"rand": 4
			}
		]
	}`)
	if err == nil || !strings.Contains(err.Error(), "invalid variable name") {
		t.Fatalf("expected invalid variable name rejection, got %v", err)
	}
}

func TestHeaderCustomUDPBuildRejectsExprWithoutArgs(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(HeaderCustomUDP) })

	_, err := parser(`{
		"client": [
			{
				"transform": {
					"op": "concat"
				}
			}
		]
	}`)
	if err == nil || !strings.Contains(err.Error(), "transform args") {
		t.Fatalf("expected transform arg rejection, got %v", err)
	}
}
