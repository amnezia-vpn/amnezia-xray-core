package router_test

import (
	"context"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	. "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

type staticOutboundManager struct {
	outbound.Manager
}

func (*staticOutboundManager) Select([]string) []string {
	return []string{"selected"}
}

type orderedOutboundManager struct {
	outbound.Manager
}

func (*orderedOutboundManager) Select([]string) []string {
	return []string{"first", "second"}
}

func TestRouterReplaceRuleSetCAS(t *testing.T) {
	r := new(Router)
	if err := r.Init(context.Background(), ruleSetConfig("initial", "initial-rule"), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})

	initialVersion, initialConfig, err := r.GetRuleSet()
	if err != nil {
		t.Fatal(err)
	}
	if initialVersion.InstanceID == "" {
		t.Fatal("initial instance ID is empty")
	}
	if initialVersion.Generation != 1 {
		t.Fatalf("initial generation = %d, want 1", initialVersion.Generation)
	}

	initialConfig.Value[0] ^= 0xff
	_, freshConfig, err := r.GetRuleSet()
	if err != nil {
		t.Fatal(err)
	}
	if got := decodedRuleSet(t, freshConfig).Rule[0].GetTag(); got != "initial" {
		t.Fatalf("stored config changed through returned value: got %q", got)
	}

	replacement := serial.ToTypedMessage(ruleSetConfig("replacement", "replacement-rule"))
	replacedVersion, err := r.ReplaceRuleSet(initialVersion, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if replacedVersion.InstanceID != initialVersion.InstanceID {
		t.Fatalf("instance ID changed: got %q, want %q", replacedVersion.InstanceID, initialVersion.InstanceID)
	}
	if replacedVersion.Generation != initialVersion.Generation+1 {
		t.Fatalf("generation = %d, want %d", replacedVersion.Generation, initialVersion.Generation+1)
	}
	if got := pickedOutbound(t, r); got != "replacement" {
		t.Fatalf("outbound after replacement = %q, want replacement", got)
	}

	if _, err := r.ReplaceRuleSet(RuleSetVersion{
		InstanceID: replacedVersion.InstanceID,
	}, serial.ToTypedMessage(ruleSetConfig("missing-generation", "missing-generation-rule"))); !stderrors.Is(err, ErrRuleSetInvalidVersion) {
		t.Fatalf("missing-generation replacement error = %v, want invalid version", err)
	}
	if _, err := r.ReplaceRuleSet(initialVersion, serial.ToTypedMessage(ruleSetConfig("stale", "stale-rule"))); !stderrors.Is(err, ErrRuleSetGenerationConflict) {
		t.Fatalf("stale replacement error = %v, want generation conflict", err)
	}
	if _, err := r.ReplaceRuleSet(RuleSetVersion{
		InstanceID: "other-instance",
		Generation: replacedVersion.Generation,
	}, serial.ToTypedMessage(ruleSetConfig("other", "other-rule"))); !stderrors.Is(err, ErrRuleSetInstanceMismatch) {
		t.Fatalf("wrong-instance replacement error = %v, want instance mismatch", err)
	}

	invalidConfigs := []struct {
		name   string
		config *Config
	}{
		{
			name: "conditionless rule",
			config: &Config{Rule: []*RoutingRule{{
				TargetTag: &RoutingRule_Tag{Tag: "invalid"},
			}}},
		},
		{
			name: "invalid attribute regexp",
			config: &Config{Rule: []*RoutingRule{{
				TargetTag: &RoutingRule_Tag{Tag: "invalid"},
				Attributes: map[string]string{
					"header": "[",
				},
			}}},
		},
		{
			name: "missing balancer",
			config: &Config{Rule: []*RoutingRule{{
				TargetTag: &RoutingRule_BalancingTag{BalancingTag: "missing"},
				Networks:  []net.Network{net.Network_TCP},
			}}},
		},
		{
			name: "invalid network",
			config: &Config{Rule: []*RoutingRule{{
				TargetTag: &RoutingRule_Tag{Tag: "invalid"},
				Networks:  []net.Network{net.Network(100)},
			}}},
		},
		{
			name: "nil domain matcher",
			config: &Config{Rule: []*RoutingRule{{
				TargetTag: &RoutingRule_Tag{Tag: "invalid"},
				Domain:    []*geodata.DomainRule{nil},
			}}},
		},
		{
			name: "balancer context initialization",
			config: &Config{BalancingRule: []*BalancingRule{{
				Tag:      "least-ping",
				Strategy: "leastping",
			}}},
		},
	}
	for _, test := range invalidConfigs {
		t.Run(test.name, func(t *testing.T) {
			if _, err := r.ReplaceRuleSet(replacedVersion, serial.ToTypedMessage(test.config)); err == nil {
				t.Fatal("invalid replacement succeeded")
			}
			currentVersion, _, err := r.GetRuleSet()
			if err != nil {
				t.Fatal(err)
			}
			if currentVersion != replacedVersion {
				t.Fatalf("version changed after failed replacement: got %+v, want %+v", currentVersion, replacedVersion)
			}
			if got := pickedOutbound(t, r); got != "replacement" {
				t.Fatalf("outbound changed after failed replacement: got %q", got)
			}
		})
	}
}

func TestRouterLegacyMutationsUseSnapshots(t *testing.T) {
	r := new(Router)
	if err := r.Init(context.Background(), ruleSetConfig("initial", "initial-rule"), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})

	initialVersion, _, err := r.GetRuleSet()
	if err != nil {
		t.Fatal(err)
	}
	addition := &Config{Rule: []*RoutingRule{{
		TargetTag: &RoutingRule_Tag{Tag: "udp"},
		RuleTag:   "udp-rule",
		Networks:  []net.Network{net.Network_UDP},
	}}}
	if err := r.AddRule(serial.ToTypedMessage(addition), true); err != nil {
		t.Fatal(err)
	}
	addedVersion, _, err := r.GetRuleSet()
	if err != nil {
		t.Fatal(err)
	}
	if addedVersion.Generation != initialVersion.Generation+1 {
		t.Fatalf("generation after add = %d, want %d", addedVersion.Generation, initialVersion.Generation+1)
	}
	if got := len(r.ListRule()); got != 2 {
		t.Fatalf("rule count after add = %d, want 2", got)
	}

	duplicate := &Config{Rule: []*RoutingRule{{
		TargetTag: &RoutingRule_Tag{Tag: "duplicate"},
		RuleTag:   "udp-rule",
		Networks:  []net.Network{net.Network_TCP},
	}}}
	if err := r.AddRule(serial.ToTypedMessage(duplicate), true); err == nil {
		t.Fatal("duplicate rule add succeeded")
	}
	afterFailure, _, err := r.GetRuleSet()
	if err != nil {
		t.Fatal(err)
	}
	if afterFailure != addedVersion {
		t.Fatalf("version changed after failed add: got %+v, want %+v", afterFailure, addedVersion)
	}

	if err := r.RemoveRule("udp-rule"); err != nil {
		t.Fatal(err)
	}
	removedVersion, _, err := r.GetRuleSet()
	if err != nil {
		t.Fatal(err)
	}
	if removedVersion.Generation != addedVersion.Generation+1 {
		t.Fatalf("generation after remove = %d, want %d", removedVersion.Generation, addedVersion.Generation+1)
	}
	if got := len(r.ListRule()); got != 1 {
		t.Fatalf("rule count after remove = %d, want 1", got)
	}

	if err := r.RemoveRule("not-present"); err != nil {
		t.Fatal(err)
	}
	afterNoop, _, err := r.GetRuleSet()
	if err != nil {
		t.Fatal(err)
	}
	if afterNoop != removedVersion {
		t.Fatalf("version changed after no-op remove: got %+v, want %+v", afterNoop, removedVersion)
	}
}

func TestRouterMutationsPreserveBalancerOverride(t *testing.T) {
	manager := &staticOutboundManager{}
	r := new(Router)
	if err := r.Init(context.Background(), balancedRuleSetConfig(), nil, manager, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})

	const overrideTarget = "forced"
	if err := r.SetOverrideTarget("balance", overrideTarget); err != nil {
		t.Fatal(err)
	}
	assertOverride := func() {
		t.Helper()
		target, err := r.GetOverrideTarget("balance")
		if err != nil {
			t.Fatal(err)
		}
		if target != overrideTarget {
			t.Fatalf("override target = %q, want %q", target, overrideTarget)
		}
	}

	version, _, err := r.GetRuleSet()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReplaceRuleSet(version, serial.ToTypedMessage(balancedRuleSetConfig())); err != nil {
		t.Fatal(err)
	}
	assertOverride()

	addition := &Config{Rule: []*RoutingRule{{
		TargetTag: &RoutingRule_Tag{Tag: "udp"},
		RuleTag:   "udp-rule",
		Networks:  []net.Network{net.Network_UDP},
	}}}
	if err := r.AddRule(serial.ToTypedMessage(addition), true); err != nil {
		t.Fatal(err)
	}
	assertOverride()

	if err := r.RemoveRule("udp-rule"); err != nil {
		t.Fatal(err)
	}
	assertOverride()
}

func TestRouterMutationsPreserveRoundRobinCursor(t *testing.T) {
	r := new(Router)
	config := &Config{
		Rule: []*RoutingRule{{
			TargetTag: &RoutingRule_BalancingTag{BalancingTag: "balance"},
			RuleTag:   "balanced-rule",
			Networks:  []net.Network{net.Network_TCP},
		}},
		BalancingRule: []*BalancingRule{{
			Tag:              "balance",
			OutboundSelector: []string{"candidate"},
			Strategy:         "roundRobin",
		}},
	}
	if err := r.Init(context.Background(), config, nil, &orderedOutboundManager{}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})

	if got := pickedOutbound(t, r); got != "first" {
		t.Fatalf("first round-robin selection = %q, want first", got)
	}
	if err := r.AddRule(serial.ToTypedMessage(&Config{Rule: []*RoutingRule{{
		TargetTag: &RoutingRule_Tag{Tag: "udp"},
		RuleTag:   "udp-rule",
		Networks:  []net.Network{net.Network_UDP},
	}}}), true); err != nil {
		t.Fatal(err)
	}
	if got := pickedOutbound(t, r); got != "second" {
		t.Fatalf("selection after unrelated rule update = %q, want second", got)
	}
}

func TestRouterReplaceRejectsUnavailableObservatory(t *testing.T) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	r := new(Router)
	if err := r.Init(ctx, ruleSetConfig("initial", "initial-rule"), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})

	version, _, err := r.GetRuleSet()
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.ReplaceRuleSet(version, serial.ToTypedMessage(&Config{
		BalancingRule: []*BalancingRule{{
			Tag:      "least-ping",
			Strategy: "leastPing",
		}},
	}))
	if err == nil {
		t.Fatal("replacement without Observatory succeeded")
	}
	current, _, getErr := r.GetRuleSet()
	if getErr != nil {
		t.Fatal(getErr)
	}
	if current != version {
		t.Fatalf("version changed after dependency failure: got %+v, want %+v", current, version)
	}
}

func TestRouterConcurrentSnapshotAccess(t *testing.T) {
	manager := &staticOutboundManager{}
	r := new(Router)
	config := balancedRuleSetConfig()
	if err := r.Init(context.Background(), config, nil, manager, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})

	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	recordError := func(err error) {
		if err != nil {
			errOnce.Do(func() {
				firstErr = err
			})
		}
	}

	const (
		readerCount = 8
		iterations  = 100
	)
	for range readerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				if _, err := r.PickRoute(tcpRoutingContext()); err != nil {
					recordError(err)
					return
				}
				if len(r.ListRule()) != 1 {
					recordError(stderrors.New("unexpected rule count"))
					return
				}
				if _, _, err := r.GetRuleSet(); err != nil {
					recordError(err)
					return
				}
				if err := r.SetOverrideTarget("balance", ""); err != nil {
					recordError(err)
					return
				}
				if _, err := r.GetOverrideTarget("balance"); err != nil {
					recordError(err)
					return
				}
				if _, err := r.GetPrincipleTarget("balance"); err != nil {
					recordError(err)
					return
				}
				if err := r.OverrideBalancer("balance", ""); err != nil {
					recordError(err)
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range iterations {
			version, _, err := r.GetRuleSet()
			if err != nil {
				recordError(err)
				return
			}
			if _, err := r.ReplaceRuleSet(version, serial.ToTypedMessage(config)); err != nil {
				recordError(err)
				return
			}
		}
	}()

	wg.Wait()
	if firstErr != nil {
		t.Fatal(firstErr)
	}
}

func TestRouterReturnedRouteOutlivesSnapshot(t *testing.T) {
	r := new(Router)
	if err := r.Init(context.Background(), ruleSetConfig("initial", "initial-rule"), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})

	route, err := r.PickRoute(tcpRoutingContext())
	if err != nil {
		t.Fatal(err)
	}
	version, _, err := r.GetRuleSet()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReplaceRuleSet(version, serial.ToTypedMessage(ruleSetConfig("replacement", "replacement-rule"))); err != nil {
		t.Fatal(err)
	}

	if got := route.GetOutboundTag(); got != "initial" {
		t.Fatalf("retired route outbound = %q, want initial", got)
	}
	if got := route.GetRuleTag(); got != "initial-rule" {
		t.Fatalf("retired route rule tag = %q, want initial-rule", got)
	}
}

func TestRouterReplaceWaitsForRetiredWebhook(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(requestStarted)
		<-releaseRequest
	}))
	defer server.Close()

	initial := ruleSetConfig("initial", "initial-rule")
	initial.Rule[0].Webhook = &WebhookConfig{Url: server.URL}
	r := new(Router)
	if err := r.Init(context.Background(), initial, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})

	version, _, err := r.GetRuleSet()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.PickRoute(tcpRoutingContext()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("webhook request did not start")
	}

	replaceResult := make(chan error, 1)
	go func() {
		_, err := r.ReplaceRuleSet(version, serial.ToTypedMessage(ruleSetConfig("replacement", "replacement-rule")))
		replaceResult <- err
	}()

	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		current, _, err := r.GetRuleSet()
		if err != nil {
			t.Fatal(err)
		}
		if current.Generation == version.Generation+1 {
			break
		}
		select {
		case err := <-replaceResult:
			t.Fatalf("replacement returned before publishing the new snapshot: %v", err)
		case <-deadline.C:
			t.Fatal("replacement did not publish the new snapshot")
		case <-ticker.C:
		}
	}

	select {
	case err := <-replaceResult:
		t.Fatalf("replacement returned before the retired webhook completed: %v", err)
	default:
	}
	close(releaseRequest)
	select {
	case err := <-replaceResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement did not finish after the webhook completed")
	}
}

func ruleSetConfig(outboundTag, ruleTag string) *Config {
	return &Config{Rule: []*RoutingRule{{
		TargetTag: &RoutingRule_Tag{Tag: outboundTag},
		RuleTag:   ruleTag,
		Networks:  []net.Network{net.Network_TCP},
	}}}
}

func balancedRuleSetConfig() *Config {
	return &Config{
		Rule: []*RoutingRule{{
			TargetTag: &RoutingRule_BalancingTag{BalancingTag: "balance"},
			RuleTag:   "balanced-rule",
			Networks:  []net.Network{net.Network_TCP},
		}},
		BalancingRule: []*BalancingRule{{
			Tag:              "balance",
			OutboundSelector: []string{"selected"},
		}},
	}
}

func decodedRuleSet(t *testing.T, message *serial.TypedMessage) *Config {
	t.Helper()
	instance, err := message.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	config, ok := instance.(*Config)
	if !ok {
		t.Fatalf("decoded config has type %T", instance)
	}
	return config
}

func pickedOutbound(t *testing.T, r *Router) string {
	t.Helper()
	route, err := r.PickRoute(tcpRoutingContext())
	if err != nil {
		t.Fatal(err)
	}
	return route.GetOutboundTag()
}

func tcpRoutingContext() *routing_session.Context {
	return &routing_session.Context{
		Outbound: &session.Outbound{
			Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
		},
	}
}
