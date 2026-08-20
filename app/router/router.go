package router

import (
	"context"
	stderrors "errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routing_dns "github.com/xtls/xray-core/features/routing/dns"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrRuleSetInvalidVersion indicates that a required version field is missing.
	ErrRuleSetInvalidVersion = stderrors.New("invalid routing rule set version")
	// ErrRuleSetInstanceMismatch indicates that the caller is addressing a stale router instance.
	ErrRuleSetInstanceMismatch = stderrors.New("routing rule set instance mismatch")
	// ErrRuleSetGenerationConflict indicates that the rule set changed since the caller read it.
	ErrRuleSetGenerationConflict = stderrors.New("routing rule set generation conflict")
	// ErrRuleSetUnavailable indicates that the router has no mutable rule set.
	ErrRuleSetUnavailable = stderrors.New("routing rule set unavailable")
)

// RuleSetVersion identifies one immutable router rule set.
type RuleSetVersion struct {
	InstanceID string
	Generation uint64
}

type ruleSetState struct {
	version        RuleSetVersion
	domainStrategy Config_DomainStrategy
	rules          []*Rule
	balancers      map[string]*Balancer
	config         *Config
}

// Router is an implementation of routing.Router.
type Router struct {
	dns dns.Client

	ctx        context.Context
	ohm        outbound.Manager
	dispatcher routing.Dispatcher

	mu    sync.RWMutex
	state *ruleSetState
}

// Route is an implementation of routing.Route.
type Route struct {
	routing.Context
	outboundGroupTags []string
	outboundTag       string
	ruleTag           string
}

// Init initializes the Router.
func (r *Router) Init(ctx context.Context, config *Config, d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
	state, err := buildRuleSet(ctx, config, ohm, dispatcher)
	if err != nil {
		return err
	}
	instanceID := uuid.New()
	state.version = RuleSetVersion{
		InstanceID: instanceID.String(),
		Generation: 1,
	}

	r.mu.Lock()
	oldState := r.state
	r.ctx = ctx
	r.ohm = ohm
	r.dispatcher = dispatcher
	r.dns = d
	r.state = state
	r.mu.Unlock()

	closeRuleSet(oldState)
	return nil
}

// PickRoute implements routing.Router.
func (r *Router) PickRoute(ctx routing.Context) (routing.Route, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	state := r.state
	if state == nil {
		return nil, ErrRuleSetUnavailable
	}

	originalCtx := ctx
	rule, ctx, err := r.pickRouteInternal(state, ctx)
	if err != nil {
		return nil, err
	}
	tag, err := rule.GetTag()
	if err != nil {
		return nil, err
	}
	if rule.Webhook != nil {
		rule.Webhook.Fire(originalCtx, tag)
	}
	return &Route{Context: ctx, outboundTag: tag, ruleTag: rule.RuleTag}, nil
}

// AddRule implements routing.Router.
func (r *Router) AddRule(config *serial.TypedMessage, shouldAppend bool) error {
	ruleConfig, err := parseRuleSetConfig(config)
	if err != nil {
		return err
	}
	return r.ReloadRules(ruleConfig, shouldAppend)
}

// ReloadRules applies the legacy AddRule behavior using a copy-on-write snapshot.
// DomainStrategy remains a startup/versioned-rule-set setting for compatibility
// with the previous implementation.
func (r *Router) ReloadRules(config *Config, shouldAppend bool) error {
	if config == nil {
		return errors.New("routing rule set config is nil")
	}
	addition := cloneRuleSetConfig(config)

	return r.mutateRuleSet(func(current *Config) (*Config, bool, error) {
		if !shouldAppend {
			addition.DomainStrategy = current.DomainStrategy
			return cloneRuleSetConfig(addition), true, nil
		}
		if len(addition.Rule) == 0 && len(addition.BalancingRule) == 0 {
			return current, false, nil
		}
		appended := cloneRuleSetConfig(addition)
		current.Rule = append(current.Rule, appended.Rule...)
		current.BalancingRule = append(current.BalancingRule, appended.BalancingRule...)
		return current, true, nil
	})
}

// RuleExists reports whether the current rule set contains tag.
func (r *Router) RuleExists(tag string) bool {
	if tag == "" {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.state == nil {
		return false
	}
	for _, rule := range r.state.rules {
		if rule.RuleTag == tag {
			return true
		}
	}
	return false
}

// RemoveRule implements routing.Router.
func (r *Router) RemoveRule(tag string) error {
	if tag == "" {
		return errors.New("empty tag name")
	}

	return r.mutateRuleSet(func(current *Config) (*Config, bool, error) {
		rules := make([]*RoutingRule, 0, len(current.Rule))
		removed := false
		for _, rule := range current.Rule {
			if rule.GetRuleTag() == tag {
				removed = true
				continue
			}
			rules = append(rules, rule)
		}
		if !removed {
			return current, false, nil
		}
		current.Rule = rules
		return current, true, nil
	})
}

// ListRule implements routing.Router.
func (r *Router) ListRule() []routing.Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.state == nil {
		return nil
	}

	ruleList := make([]routing.Route, 0, len(r.state.rules))
	for _, rule := range r.state.rules {
		ruleList = append(ruleList, &Route{
			outboundTag: rule.Tag,
			ruleTag:     rule.RuleTag,
		})
	}
	return ruleList
}

// GetRuleSet returns a defensive copy of the current rule set and its version.
func (r *Router) GetRuleSet() (RuleSetVersion, *serial.TypedMessage, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.state == nil {
		return RuleSetVersion{}, nil, ErrRuleSetUnavailable
	}
	return r.state.version, serial.ToTypedMessage(r.state.config), nil
}

// GetRuleSetVersion returns the current version without serializing the config.
func (r *Router) GetRuleSetVersion() (RuleSetVersion, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.state == nil {
		return RuleSetVersion{}, ErrRuleSetUnavailable
	}
	return r.state.version, nil
}

// ReplaceRuleSet atomically publishes config when expected still identifies the
// current rule set. The current state is left unchanged on validation errors or
// version conflicts.
func (r *Router) ReplaceRuleSet(expected RuleSetVersion, config *serial.TypedMessage) (RuleSetVersion, error) {
	ruleConfig, err := parseRuleSetConfig(config)
	if err != nil {
		return RuleSetVersion{}, err
	}

	r.mu.RLock()
	if err := validateRuleSetVersion(r.state, expected); err != nil {
		r.mu.RUnlock()
		return RuleSetVersion{}, err
	}
	ctx, ohm, dispatcher := r.ctx, r.ohm, r.dispatcher
	r.mu.RUnlock()

	if err := validateRuleSetRuntimeDependencies(ctx, ruleConfig); err != nil {
		return RuleSetVersion{}, err
	}
	candidate, err := buildRuleSet(ctx, ruleConfig, ohm, dispatcher)
	if err != nil {
		return RuleSetVersion{}, err
	}

	r.mu.Lock()
	if err := validateRuleSetVersion(r.state, expected); err != nil {
		r.mu.Unlock()
		closeRuleSet(candidate)
		return RuleSetVersion{}, err
	}
	if r.state.version.Generation == math.MaxUint64 {
		r.mu.Unlock()
		closeRuleSet(candidate)
		return RuleSetVersion{}, ErrRuleSetUnavailable
	}
	candidate.version = RuleSetVersion{
		InstanceID: r.state.version.InstanceID,
		Generation: r.state.version.Generation + 1,
	}
	oldState := r.state
	preserveBalancerRuntimeState(oldState, candidate)
	r.state = candidate
	version := candidate.version
	r.mu.Unlock()

	closeRuleSet(oldState)
	return version, nil
}

func (r *Router) mutateRuleSet(mutate func(*Config) (*Config, bool, error)) error {
	for {
		r.mu.RLock()
		if r.state == nil {
			r.mu.RUnlock()
			return ErrRuleSetUnavailable
		}
		baseVersion := r.state.version
		current := cloneRuleSetConfig(r.state.config)
		ctx, ohm, dispatcher := r.ctx, r.ohm, r.dispatcher
		r.mu.RUnlock()

		next, changed, err := mutate(current)
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}

		if err := validateRuleSetRuntimeDependencies(ctx, next); err != nil {
			return err
		}
		candidate, err := buildRuleSet(ctx, next, ohm, dispatcher)
		if err != nil {
			return err
		}

		r.mu.Lock()
		if r.state == nil {
			r.mu.Unlock()
			closeRuleSet(candidate)
			return ErrRuleSetUnavailable
		}
		if r.state.version != baseVersion {
			r.mu.Unlock()
			closeRuleSet(candidate)
			continue
		}
		if r.state.version.Generation == math.MaxUint64 {
			r.mu.Unlock()
			closeRuleSet(candidate)
			return ErrRuleSetUnavailable
		}
		candidate.version = RuleSetVersion{
			InstanceID: r.state.version.InstanceID,
			Generation: r.state.version.Generation + 1,
		}
		oldState := r.state
		preserveBalancerRuntimeState(oldState, candidate)
		r.state = candidate
		r.mu.Unlock()

		closeRuleSet(oldState)
		return nil
	}
}

func validateRuleSetVersion(state *ruleSetState, expected RuleSetVersion) error {
	if expected.InstanceID == "" || expected.Generation == 0 {
		return ErrRuleSetInvalidVersion
	}
	if state == nil {
		return ErrRuleSetUnavailable
	}
	if expected.InstanceID != state.version.InstanceID {
		return fmt.Errorf(
			"%w: expected instance %q, current instance %q",
			ErrRuleSetInstanceMismatch,
			expected.InstanceID,
			state.version.InstanceID,
		)
	}
	if expected.Generation != state.version.Generation {
		return fmt.Errorf(
			"%w: expected generation %d, current generation %d",
			ErrRuleSetGenerationConflict,
			expected.Generation,
			state.version.Generation,
		)
	}
	return nil
}

func parseRuleSetConfig(message *serial.TypedMessage) (*Config, error) {
	if message == nil {
		return nil, errors.New("routing rule set config is nil")
	}
	instance, err := message.GetInstance()
	if err != nil {
		return nil, errors.New("failed to parse routing rule set config").Base(err)
	}
	config, ok := instance.(*Config)
	if !ok {
		return nil, errors.New("routing rule set config type is invalid")
	}
	return config, nil
}

func cloneRuleSetConfig(config *Config) *Config {
	if config == nil {
		return nil
	}
	return proto.Clone(config).(*Config)
}

func buildRuleSet(
	ctx context.Context,
	config *Config,
	ohm outbound.Manager,
	dispatcher routing.Dispatcher,
) (*ruleSetState, error) {
	if config == nil {
		return nil, errors.New("routing rule set config is nil")
	}
	config = cloneRuleSetConfig(config)
	switch config.DomainStrategy {
	case Config_AsIs, Config_IpIfNonMatch, Config_IpOnDemand:
	default:
		return nil, errors.New("invalid domain strategy: ", config.DomainStrategy)
	}

	state := &ruleSetState{
		domainStrategy: config.DomainStrategy,
		balancers:      make(map[string]*Balancer, len(config.BalancingRule)),
		rules:          make([]*Rule, 0, len(config.Rule)),
		config:         config,
	}

	for index, balancingRule := range config.BalancingRule {
		if balancingRule == nil {
			return nil, errors.New("nil balancing rule at index ", index)
		}
		if _, found := state.balancers[balancingRule.Tag]; found {
			return nil, errors.New("duplicate balancer tag: ", balancingRule.Tag)
		}
		if strings.EqualFold(balancingRule.Strategy, "leastload") && balancingRule.StrategySettings == nil {
			return nil, errors.New("leastload balancer ", balancingRule.Tag, " has no strategy settings")
		}
		balancer, err := buildBalancer(ctx, balancingRule, ohm, dispatcher)
		if err != nil {
			return nil, errors.New("failed to build balancer ", balancingRule.Tag).Base(err)
		}
		if strategy, ok := balancer.strategy.(*LeastLoadStrategy); ok {
			for costIndex, cost := range strategy.settings.Costs {
				if cost == nil {
					return nil, errors.New(
						"leastload balancer ",
						balancingRule.Tag,
						" has nil cost at index ",
						costIndex,
					)
				}
			}
		}
		state.balancers[balancingRule.Tag] = balancer
	}

	ruleTags := make(map[string]struct{}, len(config.Rule))
	for index, routingRule := range config.Rule {
		if routingRule == nil {
			closeRuleSet(state)
			return nil, errors.New("nil routing rule at index ", index)
		}
		if routingRule.GetTag() == "" && routingRule.GetBalancingTag() == "" {
			closeRuleSet(state)
			return nil, errors.New("routing rule at index ", index, " has no target tag")
		}
		if tag := routingRule.GetRuleTag(); tag != "" {
			if _, found := ruleTags[tag]; found {
				closeRuleSet(state)
				return nil, errors.New("duplicate ruleTag ", tag)
			}
			ruleTags[tag] = struct{}{}
		}
		for key, value := range routingRule.Attributes {
			if _, err := regexp.Compile(value); err != nil {
				closeRuleSet(state)
				return nil, errors.New("invalid attribute regexp for ", key).Base(err)
			}
		}
		for _, network := range routingRule.Networks {
			switch network {
			case xnet.Network_Unknown, xnet.Network_TCP, xnet.Network_UDP, xnet.Network_UNIX:
			default:
				closeRuleSet(state)
				return nil, errors.New("invalid network ", network, " in routing rule at index ", index)
			}
		}

		condition, err := buildRoutingCondition(routingRule)
		if err != nil {
			closeRuleSet(state)
			return nil, errors.New("failed to build routing rule at index ", index).Base(err)
		}
		rule := &Rule{
			Condition: condition,
			Tag:       routingRule.GetTag(),
			RuleTag:   routingRule.GetRuleTag(),
		}
		if balancerTag := routingRule.GetBalancingTag(); balancerTag != "" {
			balancer, found := state.balancers[balancerTag]
			if !found {
				closeRuleSet(state)
				return nil, errors.New("balancer ", balancerTag, " not found")
			}
			rule.Balancer = balancer
		}
		if webhookConfig := routingRule.GetWebhook(); webhookConfig != nil {
			notifier, err := NewWebhookNotifier(webhookConfig)
			if err != nil {
				closeRuleSet(state)
				return nil, errors.New("failed to build webhook for routing rule at index ", index).Base(err)
			}
			rule.Webhook = notifier
		}
		state.rules = append(state.rules, rule)
	}

	return state, nil
}

func buildBalancer(
	ctx context.Context,
	config *BalancingRule,
	ohm outbound.Manager,
	dispatcher routing.Dispatcher,
) (balancer *Balancer, err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("balancer initialization panicked: %v", value)
			balancer = nil
		}
	}()

	balancer, err = config.Build(ohm, dispatcher)
	if err == nil {
		balancer.InjectContext(ctx)
	}
	return balancer, err
}

func buildRoutingCondition(config *RoutingRule) (condition Condition, err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("routing condition initialization panicked: %v", value)
			condition = nil
		}
	}()
	return config.BuildCondition()
}

func validateRuleSetRuntimeDependencies(ctx context.Context, config *Config) error {
	if !ruleSetRequiresObservatory(config) {
		return nil
	}
	instance := core.FromContext(ctx)
	if instance == nil {
		return errors.New("routing rule set requires an Xray instance with Observatory")
	}
	if instance.GetFeature(extension.ObservatoryType()) == nil {
		return errors.New("routing rule set requires the Observatory feature")
	}
	return nil
}

func ruleSetRequiresObservatory(config *Config) bool {
	if config == nil {
		return false
	}
	for _, rule := range config.BalancingRule {
		if rule == nil {
			continue
		}
		switch strings.ToLower(rule.Strategy) {
		case "leastping", "leastload":
			return true
		case "", "random", "roundrobin":
			if rule.FallbackTag != "" {
				return true
			}
		}
	}
	return false
}

func closeRuleSet(state *ruleSetState) {
	if state == nil {
		return
	}
	for _, rule := range state.rules {
		if rule.Webhook != nil {
			_ = rule.Webhook.Close()
		}
	}
}

// preserveBalancerRuntimeState keeps a logically unchanged balancer alive
// across a snapshot replacement. This preserves strategy state such as the
// round-robin cursor as well as the runtime override. When the balancer config
// changed, only its override is carried forward. The caller must hold Router.mu
// for writing so route selection and override updates cannot race the transfer.
func preserveBalancerRuntimeState(current, candidate *ruleSetState) {
	if current == nil || candidate == nil {
		return
	}
	for tag, candidateBalancer := range candidate.balancers {
		currentBalancer, found := current.balancers[tag]
		if !found {
			continue
		}
		currentConfig := balancingRuleByTag(current.config, tag)
		candidateConfig := balancingRuleByTag(candidate.config, tag)
		if currentConfig != nil && candidateConfig != nil && proto.Equal(currentConfig, candidateConfig) {
			candidate.balancers[tag] = currentBalancer
			for _, rule := range candidate.rules {
				if rule.Balancer == candidateBalancer {
					rule.Balancer = currentBalancer
				}
			}
			continue
		}
		candidateBalancer.override.Put(currentBalancer.override.Get())
	}
}

func balancingRuleByTag(config *Config, tag string) *BalancingRule {
	if config == nil {
		return nil
	}
	for _, rule := range config.BalancingRule {
		if rule != nil && rule.Tag == tag {
			return rule
		}
	}
	return nil
}

func (r *Router) pickRouteInternal(state *ruleSetState, ctx routing.Context) (*Rule, routing.Context, error) {
	// SkipDNSResolve is set from DNS module.
	// the DOH remote server maybe a domain name,
	// this prevents cycle resolving dead loop
	skipDNSResolve := ctx.GetSkipDNSResolve()

	if state.domainStrategy == Config_IpOnDemand && !skipDNSResolve {
		ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)
	}

	for _, rule := range state.rules {
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	if state.domainStrategy != Config_IpIfNonMatch || len(ctx.GetTargetDomain()) == 0 || skipDNSResolve {
		return nil, ctx, common.ErrNoClue
	}

	ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)

	// Try applying rules again if we have IPs.
	for _, rule := range state.rules {
		if rule.Apply(ctx) {
			return rule, ctx, nil
		}
	}

	return nil, ctx, common.ErrNoClue
}

// Start implements common.Runnable.
func (r *Router) Start() error {
	return nil
}

// Close implements common.Closable.
func (r *Router) Close() error {
	r.mu.Lock()
	oldState := r.state
	r.state = nil
	r.mu.Unlock()

	closeRuleSet(oldState)
	return nil
}

// Type implements common.HasType.
func (*Router) Type() interface{} {
	return routing.RouterType()
}

// GetOutboundGroupTags implements routing.Route.
func (r *Route) GetOutboundGroupTags() []string {
	return r.outboundGroupTags
}

// GetOutboundTag implements routing.Route.
func (r *Route) GetOutboundTag() string {
	return r.outboundTag
}

func (r *Route) GetRuleTag() string {
	return r.ruleTag
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		r := new(Router)
		if err := core.RequireFeatures(ctx, func(d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
			return r.Init(ctx, config.(*Config), d, ohm, dispatcher)
		}); err != nil {
			return nil, err
		}
		return r, nil
	}))
}
