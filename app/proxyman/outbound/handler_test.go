package outbound_test

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	. "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

func TestInterfaces(t *testing.T) {
	_ = outbound.Handler(new(Handler))
	_ = outbound.Manager(new(Manager))
}

const xrayKey core.XrayKey = 1

func TestOutboundWithoutStatCounter(t *testing.T) {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{
				System: &policy.SystemPolicy{
					Stats: &policy.SystemPolicy_Stats{
						InboundUplink: true,
					},
				},
			}),
		},
	}

	v, _ := core.New(config)
	v.AddFeature(outbound.Manager(new(Manager)))
	ctx := context.WithValue(context.Background(), xrayKey, v)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	h, _ := NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag:           "tag",
		ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
	})
	conn, _ := h.(*Handler).Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), 13146))
	_, ok := conn.(*stat.CounterConnection)
	if ok {
		t.Errorf("Expected conn to not be CounterConnection")
	}
}

func TestOutboundWithStatCounter(t *testing.T) {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{
				System: &policy.SystemPolicy{
					Stats: &policy.SystemPolicy_Stats{
						OutboundUplink:   true,
						OutboundDownlink: true,
					},
				},
			}),
		},
	}

	v, _ := core.New(config)
	v.AddFeature(outbound.Manager(new(Manager)))
	ctx := context.WithValue(context.Background(), xrayKey, v)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	h, _ := NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag:           "tag",
		ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
	})
	conn, _ := h.(*Handler).Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), 13146))
	_, ok := conn.(*stat.CounterConnection)
	if !ok {
		t.Errorf("Expected conn to be CounterConnection")
	}
}

func TestNewHandlerRejectsStrictBindingProxyChain(t *testing.T) {
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	v.AddFeature(outbound.Manager(new(Manager)))
	ctx := context.WithValue(context.Background(), xrayKey, v)

	_, err = NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag: "strict",
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
			StreamSettings: &internet.StreamConfig{
				SocketSettings: &internet.SocketConfig{
					Mark:          100,
					StrictBinding: true,
				},
			},
			ProxySettings: &internet.ProxyConfig{Tag: "chain"},
		}),
		ProxySettings: serial.ToTypedMessage(&freedom.Config{
			FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
		}),
	})
	if err == nil {
		t.Fatal("strict binding with outbound proxySettings unexpectedly succeeded")
	}
	var configErr *internet.StrictBindingConfigError
	if !stderrors.As(err, &configErr) {
		t.Fatalf("error = %T %v, want StrictBindingConfigError", err, err)
	}
	if configErr.Kind != internet.StrictBindingConfigBypass {
		t.Fatalf("strict binding error kind = %q, want %q", configErr.Kind, internet.StrictBindingConfigBypass)
	}
}

func TestHandlerDialRejectsUserMarkProxyChain(t *testing.T) {
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	v.AddFeature(outbound.Manager(new(Manager)))
	ctx := context.WithValue(context.Background(), xrayKey, v)

	h, err := NewHandler(ctx, &core.OutboundHandlerConfig{
		Tag: "dynamic-mark-proxy-chain",
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
			ProxySettings: &internet.ProxyConfig{Tag: "chain"},
		}),
		ProxySettings: serial.ToTypedMessage(&freedom.Config{
			FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
		}),
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	_, err = h.(*Handler).Dial(
		session.ContextWithOutboundSocketMark(ctx, 1_000_000_000),
		net.TCPDestination(net.DomainAddress("example.com"), 443),
	)
	var configErr *internet.StrictBindingConfigError
	if !stderrors.As(err, &configErr) || configErr.Kind != internet.StrictBindingConfigBypass {
		t.Fatalf("Dial() error = %T %v, want strict-binding bypass", err, err)
	}
	if configErr.Bypass != "outbound proxySettings" {
		t.Fatalf("Dial() bypass = %q, want outbound proxySettings", configErr.Bypass)
	}
}

func TestTagsCache(t *testing.T) {
	test_duration := 10 * time.Second
	threads_num := 50
	delay := 10 * time.Millisecond
	tags_prefix := "node"

	tags := sync.Map{}
	counter := atomic.Uint64{}

	ohm, err := New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Error("failed to create outbound handler manager")
	}
	config := &core.Config{
		App: []*serial.TypedMessage{},
	}
	v, _ := core.New(config)
	v.AddFeature(ohm)
	ctx := context.WithValue(context.Background(), xrayKey, v)

	stop_add_rm := false
	wg_add_rm := sync.WaitGroup{}
	addHandlers := func() {
		defer wg_add_rm.Done()
		for !stop_add_rm {
			time.Sleep(delay)
			idx := counter.Add(1)
			tag := fmt.Sprintf("%s%d", tags_prefix, idx)
			cfg := &core.OutboundHandlerConfig{
				Tag:           tag,
				ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
			}
			if h, err := NewHandler(ctx, cfg); err == nil {
				if err := ohm.AddHandler(ctx, h); err == nil {
					// t.Log("add handler:", tag)
					tags.Store(tag, nil)
				} else {
					t.Error("failed to add handler:", tag)
				}
			} else {
				t.Error("failed to create handler:", tag)
			}
		}
	}

	rmHandlers := func() {
		defer wg_add_rm.Done()
		for !stop_add_rm {
			time.Sleep(delay)
			tags.Range(func(key interface{}, value interface{}) bool {
				if _, ok := tags.LoadAndDelete(key); ok {
					// t.Log("remove handler:", key)
					ohm.RemoveHandler(ctx, key.(string))
					return false
				}
				return true
			})
		}
	}

	selectors := []string{tags_prefix}
	wg_get := sync.WaitGroup{}
	stop_get := false
	getTags := func() {
		defer wg_get.Done()
		for !stop_get {
			time.Sleep(delay)
			_ = ohm.Select(selectors)
			// t.Logf("get tags: %v", tag)
		}
	}

	for i := 0; i < threads_num; i++ {
		wg_add_rm.Add(2)
		go rmHandlers()
		go addHandlers()
		wg_get.Add(1)
		go getTags()
	}

	time.Sleep(test_duration)
	stop_add_rm = true
	wg_add_rm.Wait()
	stop_get = true
	wg_get.Wait()
}
