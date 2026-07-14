package planner

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/domaincache"
	policyengine "router-policy/internal/policy"
	"router-policy/internal/probe"
	"router-policy/internal/tspu"
)

type RouteProber interface {
	ProbeRoute(context.Context, *config.Config, string, string, config.Service, config.Route) probe.RouteResult
}

type Options struct {
	TSPUMatch      bool
	TSPUResult     tspu.Match
	ProbeEngine    *probe.Engine
	RouteProber    RouteProber
	HealthTracker  *probe.HealthTracker
	DecisionCache  *domaincache.Manager
	ActiveRevision string
	DeviceMAC      string
	Now            func() time.Time
}

type CandidatePlan struct {
	Domain       string         `json:"domain"`
	ETLDPlusOne  string         `json:"etld_plus_one"`
	Service      string         `json:"service"`
	Category     string         `json:"category"`
	Unknown      bool           `json:"unknown"`
	TSPUStatus   string         `json:"tspu_status"`
	PolicySource string         `json:"policy_source,omitempty"`
	OverrideID   string         `json:"override_id,omitempty"`
	Candidates   []config.Route `json:"candidates"`
}

type DomainCheck struct {
	Domain       string              `json:"domain"`
	ETLDPlusOne  string              `json:"etld_plus_one"`
	Service      string              `json:"service"`
	Category     string              `json:"category"`
	TSPUStatus   string              `json:"tspu_status"`
	PolicySource string              `json:"policy_source,omitempty"`
	OverrideID   string              `json:"override_id,omitempty"`
	Cached       bool                `json:"cached"`
	Status       string              `json:"status"`
	Reason       string              `json:"reason,omitempty"`
	Confidence   float64             `json:"confidence"`
	Results      []probe.RouteResult `json:"results"`
	Selected     *probe.RouteResult  `json:"selected"`
	CheckedAt    time.Time           `json:"checked_at"`
	ExpiresAt    time.Time           `json:"expires_at"`
}

type serviceProfile struct {
	domain   string
	base     string
	name     string
	service  config.Service
	unknown  bool
	override *policyengine.MatchResult
}

func BuildCandidates(cfg *config.Config, domain, serviceName string, opts Options) (CandidatePlan, error) {
	profile, err := resolveService(cfg, domain, serviceName)
	if err != nil {
		return CandidatePlan{}, err
	}
	if err := attachPolicy(cfg, &profile, opts); err != nil {
		return CandidatePlan{}, err
	}
	return buildCandidates(cfg, profile, opts), nil
}

func CheckDomain(ctx context.Context, cfg *config.Config, domain, serviceName string, opts Options) (DomainCheck, error) {
	profile, err := resolveService(cfg, domain, serviceName)
	if err != nil {
		return DomainCheck{}, err
	}
	if err := attachPolicy(cfg, &profile, opts); err != nil {
		return DomainCheck{}, err
	}
	plan := buildCandidates(cfg, profile, opts)
	now := optionNow(opts)

	if profile.unknown && profile.override == nil && opts.DecisionCache != nil && opts.ActiveRevision != "" {
		decision, ok, err := opts.DecisionCache.Lookup(profile.domain, opts.ActiveRevision, now)
		if err != nil {
			return DomainCheck{}, fmt.Errorf("lookup cached domain decision: %w", err)
		}
		if ok {
			if cached, valid := cachedCheck(decision, plan, profile, opts.ActiveRevision); valid {
				return cached, nil
			}
		}
	}

	out := DomainCheck{
		Domain: profile.domain, ETLDPlusOne: profile.base, Service: profile.name,
		Category: profile.service.Category, TSPUStatus: plan.TSPUStatus, Status: "NO_SAFE_ROUTE",
		Reason: "no_verified_policy_allowed_route", CheckedAt: now,
	}
	if profile.override != nil {
		out.PolicySource = profile.override.Source
		out.OverrideID = profile.override.Override.ID
	}
	prober := opts.RouteProber
	if prober == nil {
		if opts.ProbeEngine != nil {
			prober = opts.ProbeEngine
		} else {
			prober = probe.NewEngine(nil)
		}
	}

	service := profile.service
	directAttempted := false
	directLookedLikeTSPU := false
	regionalBlock := false
	for _, route := range plan.Candidates {
		if regionalBlock && (route.Type == "direct" || route.Type == "zapret") {
			continue
		}
		if profile.override == nil && route.Type == "zapret" && !tspuStartsWithZapret(plan.TSPUStatus, cfg.Policy.TSPUStalePolicy) {
			if !directAttempted || !directLookedLikeTSPU {
				continue
			}
		}

		result := prober.ProbeRoute(ctx, cfg, profile.domain, profile.name, service, route)
		result = bindResultToCandidate(result, route, opts.ActiveRevision)
		out.Results = append(out.Results, result)
		if opts.HealthTracker != nil {
			opts.HealthTracker.Observe(result, cfg.Policy, optionNow(opts))
		}

		if route.Type == "direct" {
			directAttempted = true
			directLookedLikeTSPU = looksLikeTSPU(result)
		}
		if result.RegionalBlock || result.Status == "REGION_BLOCK" {
			regionalBlock = true
			service.Category = "GEO_LOCKED"
			service.RequireNonRUEgress = true
			service.AllowedPaths = []string{"smart_dns", "vless", "drop"}
			service.ForbiddenPaths = []string{"direct", "zapret"}
			out.Category = "GEO_LOCKED"
		}
		if verifiedSuccess(result) {
			selected := result
			out.Selected = &selected
			out.Status = "SELECTED"
			if route.Type == "drop" {
				out.Status = "DROP"
				out.Reason = "no_safe_route_drop_enforced"
			} else {
				out.Reason = "best_verified_policy_allowed_route"
			}
			break
		}
	}

	out.CheckedAt = optionNow(opts)
	ttl := time.Duration(cfg.Policy.DomainDecisionTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	out.ExpiresAt = out.CheckedAt.Add(ttl)
	out.Confidence = decisionConfidence(out, opts.TSPUResult)

	if profile.unknown && profile.override == nil && opts.DecisionCache != nil && opts.ActiveRevision != "" {
		decision := domaincache.Decision{
			Service: profile.name, Category: out.Category, TSPUStatus: out.TSPUStatus,
			Status: out.Status, Reason: out.Reason, AdapterRevision: opts.ActiveRevision,
			Confidence: out.Confidence, Results: out.Results, CheckedAt: out.CheckedAt,
			ExpiresAt: out.ExpiresAt, LastUsedAt: out.CheckedAt,
		}
		if out.Selected != nil {
			decision.SelectedRoute = out.Selected.Route
			decision.SelectedType = out.Selected.RouteType
		}
		if _, err := opts.DecisionCache.Save(profile.domain, decision); err != nil {
			return out, fmt.Errorf("persist domain decision: %w", err)
		}
	}
	return out, nil
}

func SelectBest(results []probe.RouteResult) *probe.RouteResult {
	var ok []probe.RouteResult
	for _, result := range results {
		if verifiedSuccess(result) {
			ok = append(ok, result)
		}
	}
	if len(ok) == 0 {
		return nil
	}
	sort.SliceStable(ok, func(i, j int) bool {
		return resultRank(ok[i]) < resultRank(ok[j])
	})
	return &ok[0]
}

func resultRank(result probe.RouteResult) int64 {
	priority := result.RoutePriority
	if priority <= 0 {
		priority = 500
	}
	return int64(priority)*1_000_000 + result.LatencyMS
}

func resolveService(cfg *config.Config, domain, serviceName string) (serviceProfile, error) {
	if cfg == nil {
		return serviceProfile{}, errors.New("config is required")
	}
	normalized, err := tspu.NormalizeDomain(domain)
	if err != nil {
		return serviceProfile{}, err
	}
	base := tspu.ETLDPlusOne(normalized)
	if service, ok := cfg.Services[serviceName]; ok {
		return serviceProfile{domain: normalized, base: base, name: serviceName, service: service}, nil
	}
	if detected := cfg.ServiceForDomain(normalized); detected != "" {
		return serviceProfile{domain: normalized, base: base, name: detected, service: cfg.Services[detected]}, nil
	}
	name := "UNKNOWN:" + base
	service := config.Service{
		Category:     "DIRECT_PREFERRED",
		Domains:      []string{normalized, base},
		AllowedPaths: []string{"direct", "zapret", "smart_dns", "vless", "drop"},
		ProbeURLs: []config.ProbeCheck{{
			Name: "unknown-domain-https", URL: "https://" + normalized + "/", Required: true,
			ExpectedCodes: unknownExpectedCodes(), BodyMode: "optional",
		}},
	}
	return serviceProfile{domain: normalized, base: base, name: name, service: service, unknown: true}, nil
}

func buildCandidates(cfg *config.Config, profile serviceProfile, opts Options) CandidatePlan {
	tspuStatus := normalizedTSPUStatus(opts)
	if profile.override != nil {
		var candidates []config.Route
		routes := cfg.Routes
		if profile.override.Override.RouteTag == "" {
			routes = cfg.RoutesByType(profile.override.Override.RouteType)
			if profile.override.Override.RouteType == "smart_dns" && opts.HealthTracker != nil {
				routes = opts.HealthTracker.OrderSmartDNS(routes)
			}
			if profile.override.Override.RouteType == "vless" && opts.HealthTracker != nil {
				routes = opts.HealthTracker.OrderVLESS(routes)
			}
		}
		if route, ok := policyengine.SelectRoute(*profile.override, routes); ok && manualRouteAllowed(profile.service, route, cfg.Policy) {
			candidates = append(candidates, route)
		}
		if len(candidates) == 0 || candidates[0].Type != "drop" {
			if drop, ok := firstEnabledRoute(cfg.RoutesByType("drop")); ok {
				candidates = append(candidates, drop)
			}
		}
		return CandidatePlan{
			Domain: profile.domain, ETLDPlusOne: profile.base, Service: profile.name,
			Category: profile.service.Category, Unknown: profile.unknown, TSPUStatus: tspuStatus,
			PolicySource: profile.override.Source, OverrideID: profile.override.Override.ID, Candidates: candidates,
		}
	}
	order := orderForService(profile.service.Category, tspuStatus, cfg.Policy.TSPUStalePolicy)
	var candidates []config.Route
	seen := map[string]bool{}
	for _, routeType := range order {
		routes := cfg.RoutesByType(routeType)
		if routeType == "drop" && len(routes) == 0 {
			routes = []config.Route{{Type: "drop", Tag: "drop", Priority: 1000}}
		}
		if routeType == "smart_dns" && opts.HealthTracker != nil {
			routes = opts.HealthTracker.OrderSmartDNS(routes)
		}
		if routeType == "vless" && opts.HealthTracker != nil {
			routes = opts.HealthTracker.OrderVLESS(routes)
		}
		for _, route := range routes {
			if seen[route.Tag] || !config.PathAllowed(profile.service, route, cfg.Policy) {
				continue
			}
			seen[route.Tag] = true
			candidates = append(candidates, route)
		}
	}
	return CandidatePlan{
		Domain: profile.domain, ETLDPlusOne: profile.base, Service: profile.name,
		Category: profile.service.Category, Unknown: profile.unknown,
		TSPUStatus: tspuStatus, Candidates: candidates,
	}
}

func attachPolicy(cfg *config.Config, profile *serviceProfile, opts Options) error {
	match, ok, err := policyengine.Match(cfg, profile.domain, opts.DeviceMAC, profile.name, profile.service.Category)
	if err != nil {
		return err
	}
	if ok {
		profile.override = &match
	}
	return nil
}

func manualRouteAllowed(service config.Service, route config.Route, policy config.Policy) bool {
	switch service.Category {
	case "DIRECT_ONLY":
		return route.Type == "direct"
	case "BLOCKED":
		return route.Type == "drop"
	case "GEO_LOCKED":
		if route.Type == "direct" && !policy.GeoLockedAllowDirect || route.Type == "zapret" && !policy.GeoLockedAllowZapret {
			return false
		}
	}
	return true
}

func firstEnabledRoute(routes []config.Route) (config.Route, bool) {
	for _, route := range routes {
		if route.Enabled() {
			return route, true
		}
	}
	return config.Route{}, false
}

func orderForService(category, tspuStatus, stalePolicy string) []string {
	switch category {
	case "DIRECT_ONLY":
		return []string{"direct"}
	case "GEO_LOCKED":
		return []string{"smart_dns", "vless", "drop"}
	case "TELEGRAM":
		return []string{"tg_ws_proxy", "vless", "drop"}
	case "TSPU_RESTRICTED":
		return []string{"zapret", "smart_dns", "vless", "drop"}
	case "BLOCKED":
		return []string{"drop"}
	case "DIRECT_PREFERRED", "":
		if tspuStatus == "MATCH" || tspuStatus == "STALE_MATCH" && stalePolicy == "zapret_first" {
			return []string{"zapret", "smart_dns", "vless", "drop"}
		}
		if tspuStatus == "STALE_MATCH" && stalePolicy == "fail_closed" {
			return []string{"drop"}
		}
		return []string{"direct", "zapret", "smart_dns", "vless", "drop"}
	default:
		return []string{"drop"}
	}
}

func normalizedTSPUStatus(opts Options) string {
	status := strings.ToUpper(strings.TrimSpace(opts.TSPUResult.Status))
	if status == "" && opts.TSPUMatch {
		status = "MATCH"
	}
	switch status {
	case "MATCH", "STALE_MATCH", "UNAVAILABLE":
		return status
	default:
		return "NO_MATCH"
	}
}

func tspuStartsWithZapret(status, stalePolicy string) bool {
	return status == "MATCH" || status == "STALE_MATCH" && stalePolicy == "zapret_first"
}

func bindResultToCandidate(result probe.RouteResult, route config.Route, activeRevision string) probe.RouteResult {
	reason := ""
	if result.Route != route.Tag || result.RouteType != route.Type {
		reason = "probe_route_identity_mismatch"
	} else if activeRevision != "" && result.AdapterRevision != activeRevision {
		reason = "probe_adapter_revision_mismatch"
	} else if (result.Status == "OK" || result.Status == "DEGRADED") && (!result.PathVerified || !result.ServiceOK) {
		reason = "probe_success_without_complete_evidence"
	}
	if reason != "" {
		result.Status = "UNVERIFIED"
		result.PathVerified = false
		result.ServiceOK = false
		result.FailureStage = "route_evidence"
		result.ReasonCode = reason
		result.Reason = &reason
	}
	return result
}

func verifiedSuccess(result probe.RouteResult) bool {
	return result.Status == "OK" && result.PathVerified && result.ServiceOK
}

func looksLikeTSPU(result probe.RouteResult) bool {
	if result.SuspectedTSPU || result.Status == "SUSPECTED_TSPU" {
		return true
	}
	for _, check := range result.Checks {
		switch check.Reason {
		case "connection_reset", "tls_failed", "timeout":
			return true
		}
	}
	return false
}

func cachedCheck(decision domaincache.Decision, plan CandidatePlan, profile serviceProfile, activeRevision string) (DomainCheck, bool) {
	if decision.AdapterRevision != activeRevision || decision.Service != profile.name || decision.TSPUStatus != plan.TSPUStatus {
		return DomainCheck{}, false
	}
	out := DomainCheck{
		Domain: profile.domain, ETLDPlusOne: profile.base, Service: decision.Service,
		Category: decision.Category, TSPUStatus: decision.TSPUStatus, Cached: true,
		Status: decision.Status, Reason: decision.Reason, Confidence: decision.Confidence,
		Results: decision.Results, CheckedAt: decision.CheckedAt, ExpiresAt: decision.ExpiresAt,
	}
	if decision.SelectedRoute == "" {
		return out, decision.Status == "NO_SAFE_ROUTE"
	}
	allowed := false
	for _, route := range plan.Candidates {
		if route.Tag == decision.SelectedRoute && route.Type == decision.SelectedType {
			allowed = true
			break
		}
	}
	if !allowed {
		return DomainCheck{}, false
	}
	for i := range out.Results {
		result := out.Results[i]
		if result.Route == decision.SelectedRoute && result.RouteType == decision.SelectedType && result.AdapterRevision == activeRevision && verifiedSuccess(result) {
			selected := result
			out.Selected = &selected
			return out, true
		}
	}
	return DomainCheck{}, false
}

func optionNow(opts Options) time.Time {
	if opts.Now != nil {
		return opts.Now().UTC()
	}
	return time.Now().UTC()
}

func decisionConfidence(check DomainCheck, match tspu.Match) float64 {
	if check.Selected == nil {
		return 0
	}
	confidence := 0.8
	if check.Selected.RouteType == "drop" {
		confidence = 0.95
	}
	if match.Status == "MATCH" && match.Confidence > confidence {
		confidence = match.Confidence
	}
	if match.Status == "STALE_MATCH" {
		confidence *= 0.7
	}
	if confidence > 1 {
		return 1
	}
	return confidence
}

func unknownExpectedCodes() []int {
	codes := make([]int, 0, 205)
	for code := 200; code < 400; code++ {
		codes = append(codes, code)
	}
	return append(codes, 401, 403, 404, 405)
}
