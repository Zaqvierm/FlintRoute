package planner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	Domain        string         `json:"domain"`
	ETLDPlusOne   string         `json:"etld_plus_one"`
	Service       string         `json:"service"`
	Category      string         `json:"category"`
	Unknown       bool           `json:"unknown"`
	TSPUStatus    string         `json:"tspu_status"`
	PolicySource  string         `json:"policy_source,omitempty"`
	OverrideID    string         `json:"override_id,omitempty"`
	InventoryHash string         `json:"candidate_inventory_hash,omitempty"`
	Candidates    []config.Route `json:"candidates"`
}

type DomainCheck struct {
	Domain                   string              `json:"domain"`
	ETLDPlusOne              string              `json:"etld_plus_one"`
	Service                  string              `json:"service"`
	Category                 string              `json:"category"`
	TSPUStatus               string              `json:"tspu_status"`
	PolicySource             string              `json:"policy_source,omitempty"`
	OverrideID               string              `json:"override_id,omitempty"`
	Cached                   bool                `json:"cached"`
	Status                   string              `json:"status"`
	Reason                   string              `json:"reason,omitempty"`
	Confidence               float64             `json:"confidence"`
	ClassificationConfidence float64             `json:"classification_confidence"`
	ClassificationSource     string              `json:"classification_source,omitempty"`
	ClassificationEvidence   string              `json:"classification_evidence,omitempty"`
	ClassificationState      string              `json:"classification_state"`
	ClassificationReason     string              `json:"classification_reason,omitempty"`
	InitialUnknownPolicy     string              `json:"initial_unknown_policy,omitempty"`
	CandidateInventoryHash   string              `json:"candidate_inventory_hash,omitempty"`
	VerificationState        string              `json:"verification_state"`
	VerificationDurationMS   int64               `json:"verification_duration_ms,omitempty"`
	Results                  []probe.RouteResult `json:"results"`
	Selected                 *probe.RouteResult  `json:"selected"`
	CheckedAt                time.Time           `json:"checked_at"`
	ExpiresAt                time.Time           `json:"expires_at"`
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
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg == nil {
		return DomainCheck{}, errors.New("config is required")
	}
	profile, err := resolveService(cfg, domain, serviceName)
	if err != nil {
		return DomainCheck{}, err
	}
	if err := attachPolicy(cfg, &profile, opts); err != nil {
		return DomainCheck{}, err
	}
	plan := buildCandidates(cfg, profile, opts)
	now := optionNow(opts)
	verificationStarted := time.Now()

	if profile.unknown && profile.override == nil && opts.DecisionCache != nil && opts.ActiveRevision != "" {
		decision, ok, err := opts.DecisionCache.Lookup(profile.domain, opts.ActiveRevision, now)
		if err != nil {
			return DomainCheck{}, fmt.Errorf("lookup cached domain decision: %w", err)
		}
		if ok {
			if cached, valid := cachedCheck(decision, plan, profile, opts.ActiveRevision); valid {
				return cached, nil
			}
			if decision.SelectedRoute == "" {
				if err := opts.DecisionCache.Discard(decision.Key); err != nil {
					return DomainCheck{}, fmt.Errorf("discard failed domain observation: %w", err)
				}
			}
		}
	}

	out := DomainCheck{
		Domain: profile.domain, ETLDPlusOne: profile.base, Service: profile.name,
		Category: profile.service.Category, TSPUStatus: plan.TSPUStatus, Status: "VERIFYING",
		VerificationState: "in_progress", CandidateInventoryHash: plan.InventoryHash, CheckedAt: now,
	}
	if profile.unknown {
		out.InitialUnknownPolicy = initialUnknownPolicy(cfg.Policy)
	}
	out.ClassificationConfidence, out.ClassificationSource, out.ClassificationEvidence = classificationMetadata(profile, opts.TSPUResult)
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
	allCandidatesTerminal := true
	for _, route := range plan.Candidates {
		if ctx.Err() != nil {
			allCandidatesTerminal = false
			break
		}
		if regionalBlock && (route.Type == "direct" || route.Type == "zapret") {
			continue
		}
		// An explicit TSPU_RESTRICTED service category is already a policy
		// eligibility decision. Do not silently skip its Zapret candidates just
		// because this invocation has no fresh TSPU detector result. The route
		// is still ranked only after terminal evidence from every candidate;
		// this guard applies only to unclassified/ordinary domains where Zapret
		// should not be probed speculatively.
		if profile.override == nil && route.Type == "zapret" &&
			!strings.EqualFold(profile.service.Category, "TSPU_RESTRICTED") &&
			!tspuStartsWithZapret(plan.TSPUStatus, cfg.Policy.TSPUStalePolicy) {
			if !directAttempted || !directLookedLikeTSPU {
				continue
			}
		}

		result := prober.ProbeRoute(ctx, cfg, profile.domain, profile.name, service, route)
		result = bindResultToCandidate(result, route, opts.ActiveRevision)
		out.Results = append(out.Results, result)
		if !probeResultTerminal(result) {
			// RouteProber is synchronous: an in-progress or malformed result is
			// not evidence that this candidate failed.  Do not let it fall
			// through to the terminal NO_SAFE_ROUTE state.
			allCandidatesTerminal = false
			break
		}
		if opts.HealthTracker != nil {
			opts.HealthTracker.Observe(result, cfg.Policy, optionNow(opts))
		}
		if ctx.Err() != nil {
			allCandidatesTerminal = false
			break
		}

		if route.Type == "direct" {
			directAttempted = true
			directLookedLikeTSPU = looksLikeTSPU(result)
		}
		// A regional denial is only a classification signal when it came from
		// the direct baseline.  A failed alternate route must not by itself
		// rewrite the service policy or make every other route ineligible.
		if route.Type == "direct" && (result.RegionalBlock || strings.EqualFold(result.Status, "REGION_BLOCK")) {
			regionalBlock = true
			service.Category = "GEO_LOCKED"
			service.RequireNonRUEgress = true
			service.AllowedPaths = []string{"smart_dns", "vless", "drop"}
			service.ForbiddenPaths = []string{"direct", "zapret"}
			out.Category = "GEO_LOCKED"
		}
		// An exact user override is an explicit policy decision. Keep the
		// verified override route and retain DROP only as its failure fallback;
		// do not benchmark unrelated routes against a forced choice.
		if profile.override != nil && selectionEvidence(result) {
			break
		}
	}
	if !allCandidatesTerminal {
		out.Status = "VERIFYING"
		out.VerificationState = "in_progress"
		out.Reason = "verification_incomplete"
		out.Confidence = 0
		out.CheckedAt = optionNow(opts)
		out.VerificationDurationMS = time.Since(verificationStarted).Milliseconds()
		return out, nil
	}
	// Score is computed only after all terminal evidence has been collected.
	// Expose the same score that drives selection so the UI cannot invent a
	// ranking from route order or verification duration.
	for i := range out.Results {
		route, ok := routeForResult(cfg, out.Results[i])
		if ok && config.PathAllowed(service, route, cfg.Policy) && selectionEvidence(out.Results[i]) {
			out.Results[i].SelectionScore = selectionScore(out.Results[i], cfg.Policy, opts.HealthTracker)
		}
	}
	allowedResults := make([]probe.RouteResult, 0, len(out.Results))
	for _, result := range out.Results {
		route, ok := routeForResult(cfg, result)
		if !ok || !config.PathAllowed(service, route, cfg.Policy) || !selectionEvidence(result) {
			continue
		}
		if service.RequireNonRUEgress && route.Type != "drop" {
			country := strings.ToUpper(strings.TrimSpace(result.ExternalCountry))
			if !result.EgressConsensus || country == "" || country == "RU" {
				continue
			}
		}
		allowedResults = append(allowedResults, result)
	}
	currentRoute := service.SelectedRouteTag
	if currentRoute == "" {
		currentRoute = currentHealthyRoute(opts.HealthTracker)
	}
	if selected := SelectBestWithPolicy(allowedResults, cfg.Policy, currentRoute, opts.HealthTracker); selected != nil {
		out.Selected = selected
		out.Status = "SELECTED"
		out.Reason = "best_verified_policy_allowed_route"
		if selected.RouteType == "drop" {
			out.Status = "DROP"
			out.Reason = "no_safe_route_drop_enforced"
		}
	}
	if out.Selected == nil {
		out.Status = "NO_SAFE_ROUTE"
		out.VerificationState = "terminal_no_safe_route"
		out.Reason = "no_verified_policy_allowed_route"
	} else {
		out.VerificationState = "verified"
	}
	out.ClassificationState, out.ClassificationReason = classifyEvidence(profile, out.Results, plan.TSPUStatus)

	out.CheckedAt = optionNow(opts)
	out.VerificationDurationMS = time.Since(verificationStarted).Milliseconds()
	ttl := time.Duration(cfg.Policy.DomainDecisionTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	out.ExpiresAt = out.CheckedAt.Add(ttl)
	out.Confidence = decisionConfidence(out, opts.TSPUResult)

	if profile.unknown && profile.override == nil && opts.DecisionCache != nil && opts.ActiveRevision != "" &&
		(out.Selected != nil || out.Status == "NO_SAFE_ROUTE") {
		decision := domaincache.Decision{
			Service: profile.name, Category: out.Category, TSPUStatus: out.TSPUStatus,
			ClassificationState: out.ClassificationState, ClassificationReason: out.ClassificationReason,
			CandidateInventoryHash: plan.InventoryHash,
			Status:                 out.Status, Reason: out.Reason, AdapterRevision: opts.ActiveRevision,
			Confidence: out.Confidence, ClassificationConfidence: out.ClassificationConfidence,
			ClassificationSource: out.ClassificationSource, ClassificationEvidence: out.ClassificationEvidence,
			VerificationDurationMS: out.VerificationDurationMS, Results: out.Results, CheckedAt: out.CheckedAt,
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

func routeForResult(cfg *config.Config, result probe.RouteResult) (config.Route, bool) {
	if result.Route == "system-default" && result.RouteType == "direct" {
		// Unknown-domain observation may probe OpenWrt's already-existing
		// default path before FlintRoute owns a managed Direct route. Keep this
		// synthetic candidate eligible for scoring without inventing an owned
		// dataplane object or making it auto-assignable.
		return config.Route{Type: "direct", Tag: "system-default", AdapterMode: "system_default"}, true
	}
	if cfg == nil {
		return config.Route{}, false
	}
	return cfg.RouteByTag(result.Route)
}

func SelectBest(results []probe.RouteResult) *probe.RouteResult {
	return SelectBestWithPolicy(results, config.Policy{}, "", nil)
}

// ScoreRouteResult exposes the same policy-aware score used by SelectBest for
// callers that need to render or rank a pre-apply candidate without inventing
// a second ordering model.
func ScoreRouteResult(result probe.RouteResult, policy config.Policy, health *probe.HealthTracker) float64 {
	return selectionScore(result, policy, health)
}

// SelectBestWithPolicy ranks only candidates that passed the complete safety
// contract. Policy order is used to build the candidate set, never as a
// winner. Hysteresis keeps a healthy current route when a new probe is only a
// negligible improvement.
func SelectBestWithPolicy(results []probe.RouteResult, policy config.Policy, currentRoute string, health *probe.HealthTracker) *probe.RouteResult {
	var ok []probe.RouteResult
	for _, result := range results {
		if selectionEvidence(result) {
			ok = append(ok, result)
		}
	}
	if len(ok) == 0 {
		return nil
	}
	sort.SliceStable(ok, func(i, j int) bool {
		left, right := selectionScore(ok[i], policy, health), selectionScore(ok[j], policy, health)
		if left != right {
			return left < right
		}
		return ok[i].Route < ok[j].Route
	})
	best := ok[0]
	if currentRoute == "" || best.Route == currentRoute {
		return &best
	}
	var current *probe.RouteResult
	for i := range ok {
		if ok[i].Route == currentRoute {
			candidate := ok[i]
			current = &candidate
			break
		}
	}
	if current == nil {
		return &best
	}
	// A failed current route is never protected by hysteresis. A current
	// route with a valid result is held unless the new candidate is materially
	// better. Defaults intentionally require a 15% improvement.
	hysteresis := policy.RouteSelectionHysteresisPercent
	if hysteresis <= 0 {
		hysteresis = 15
	}
	currentScore := selectionScore(*current, policy, health)
	bestScore := selectionScore(best, policy, health)
	if health != nil {
		if h, found := health.Get(current.Route); found && h.State == "unhealthy" {
			return &best
		}
		if cooldown := time.Duration(policy.RouteSelectionCooldownSeconds) * time.Second; cooldown > 0 {
			if h, found := health.Get(current.Route); found && h.Role == "selected" && !h.LastSuccessAt.IsZero() && time.Since(h.LastSuccessAt) < cooldown {
				return current
			}
		}
		if h, found := health.Get(best.Route); found && h.ConsecutiveSuccesses > 0 && h.ConsecutiveSuccesses < 2 {
			return current
		}
	}
	if bestScore >= currentScore*(1-float64(hysteresis)/100) {
		return current
	}
	return &best
}

func selectionEvidence(result probe.RouteResult) bool {
	if result.RouteType == "drop" {
		// A successful drop probe may report Status=OK after path proof, but
		// ApplicationStatus remains DROP. Accept only that explicit safety
		// outcome; a generic HTTP OK must never masquerade as DROP evidence.
		return strings.EqualFold(result.Status, "DROP") || strings.EqualFold(result.ApplicationStatus, "DROP")
	}
	if !strings.EqualFold(result.Status, "OK") || !result.PathVerified || !result.ServiceOK || result.RegionalBlock || strings.EqualFold(result.Status, "REGION_BLOCK") {
		return false
	}
	// DROP is a verified terminal safety outcome, not a network path. Unknown
	// latency is still valid evidence (it simply ranks after measured paths),
	// because a route may be proven safe without exposing a timing sample.
	return true
}

func selectionLatency(result probe.RouteResult) (int64, bool) {
	if result.EndToEndLatencyAvailable && result.EndToEndLatencyMS > 0 {
		return result.EndToEndLatencyMS, true
	}
	// RouteLatencyMS is a request/path measurement and is intentionally not
	// comparable across candidates that use different DNS or preparation
	// paths. Only the typed end-to-end service metric may drive scoring.
	return 0, false
}

func selectionScore(result probe.RouteResult, policy config.Policy, health *probe.HealthTracker) float64 {
	latency, known := selectionLatency(result)
	if !known {
		return 1e15
	}
	weights := policy.RouteSelectionWeights
	if weights.EndToEndLatency == 0 {
		weights.EndToEndLatency = 1
	}
	if weights.Availability == 0 {
		weights.Availability = 0.25
	}
	if weights.ErrorRate == 0 {
		weights.ErrorRate = 0.1
	}
	if weights.Privacy == 0 {
		weights.Privacy = 0.25
	}
	score := float64(latency) * weights.EndToEndLatency
	if strings.EqualFold(policy.RouteSelectionStrategy, "privacy_first") && result.RouteType == "direct" {
		score *= 1 + weights.Privacy
	}
	if health != nil {
		if h, ok := health.Get(result.Route); ok {
			if h.AvailabilityEWMA > 0 && h.AvailabilityEWMA < 1 {
				score *= 1 + (1-h.AvailabilityEWMA)*weights.Availability
			}
			if h.ConsecutiveErrors > 0 {
				score *= 1 + float64(h.ConsecutiveErrors)*weights.ErrorRate
			}
		}
	}
	return score
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
			PolicySource: profile.override.Source, OverrideID: profile.override.Override.ID,
			InventoryHash: hashCandidateInventory(candidates, profile.service, cfg.Policy, tspuStatus, opts.HealthTracker), Candidates: candidates,
		}
	}
	eligibleTypes := eligibleRouteTypesForService(profile.service.Category, tspuStatus, cfg.Policy.TSPUStalePolicy)
	unknownMode := "balanced"
	if profile.unknown {
		unknownMode = initialUnknownPolicy(cfg.Policy)
		switch unknownMode {
		case "privacy_first":
			// Privacy-first is a real candidate constraint, not a UI label: an
			// unknown domain must not be selected onto Direct while it is being
			// classified. Keep only already configured non-Direct paths and DROP.
			filtered := eligibleTypes[:0]
			for _, routeType := range eligibleTypes {
				if routeType != "direct" {
					filtered = append(filtered, routeType)
				}
			}
			eligibleTypes = filtered
		case "fail_closed":
			// Fail-closed unknown policy has no network candidate. DROP is the
			// only honest terminal outcome until an explicit rule is applied.
			eligibleTypes = []string{"drop"}
		}
	}
	var candidates []config.Route
	seen := map[string]bool{}
	// Unknown traffic is still owned by OpenWrt until a FlintRoute policy is
	// committed. Probe that real system path first instead of pretending the
	// managed Direct mark/table already exists on a clean baseline.
	if profile.unknown && unknownMode == "balanced" && !tspuStartsWithZapret(tspuStatus, cfg.Policy.TSPUStalePolicy) {
		for _, route := range cfg.RoutesByType("direct") {
			if route.Enabled() && route.RequiresAdapter {
				candidates = append(candidates, config.Route{
					Type: "direct", Tag: "system-default", Priority: route.Priority - 1,
					AdapterMode: "system_default", ForbidProxy: true,
				})
				seen["system-default"] = true
				break
			}
		}
	}
	selectedRoute, selectedRouteOK := cfg.RouteByTag(profile.service.SelectedRouteTag)
	if profile.service.SelectedRouteTag != "" {
		if !selectedRouteOK || !config.PathAllowed(profile.service, selectedRoute, cfg.Policy) {
			selectedRouteOK = false
		}
	}
	for _, routeType := range eligibleTypes {
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
		if selectedRouteOK && selectedRoute.Type == routeType && selectedRoute.Enabled() {
			candidates = append(candidates, selectedRoute)
			seen[selectedRoute.Tag] = true
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
		TSPUStatus: tspuStatus, InventoryHash: hashCandidateInventory(candidates, profile.service, cfg.Policy, tspuStatus, opts.HealthTracker), Candidates: candidates,
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

// eligibleRouteTypesForService returns policy eligibility only. Its order is a
// bounded collection order and is never used as the route winner; all returned
// candidates are probed and later ranked by evidence.
func eligibleRouteTypesForService(category, tspuStatus, stalePolicy string) []string {
	switch category {
	case "DIRECT_ONLY":
		return []string{"direct"}
	case "GEO_LOCKED":
		return []string{"smart_dns", "vless", "drop"}
	case "TELEGRAM":
		return []string{"external_socks", "vless", "drop"}
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
	if route.AdapterMode == "system_default" && result.PathVerified && result.AdapterRevision == "" {
		result.AdapterRevision = activeRevision
	}
	statusOK := strings.EqualFold(strings.TrimSpace(result.Status), "OK")
	statusDegraded := strings.EqualFold(strings.TrimSpace(result.Status), "DEGRADED")
	reason := ""
	if result.Route != route.Tag || result.RouteType != route.Type {
		reason = "probe_route_identity_mismatch"
	} else if activeRevision != "" && result.AdapterRevision != activeRevision &&
		(result.PathVerified || statusOK || statusDegraded) {
		reason = "probe_adapter_revision_mismatch"
	} else if (statusOK || statusDegraded) && (!result.PathVerified || !result.ServiceOK) {
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

func probeResultTerminal(result probe.RouteResult) bool {
	switch strings.ToUpper(strings.TrimSpace(result.Status)) {
	case "", "VERIFYING", "PROBING", "WAITING", "WAITING_FOR_VERIFICATION", "IN_PROGRESS":
		return false
	case "FAIL", "OK", "DEGRADED", "NOT_CONFIGURED", "NOT_APPLICABLE", "UNVERIFIED",
		"RU_EXIT", "REGION_BLOCK", "SUSPECTED_TSPU", "AUTH_REQUIRED", "WAF_OR_RATE_LIMIT", "DROP", "TIMEOUT", "ERROR":
		return true
	default:
		// Unknown evidence is malformed, not proof that the candidate reached
		// a terminal result. Keep verification open instead of manufacturing
		// NO_SAFE_ROUTE.
		return false
	}
}

func looksLikeTSPU(result probe.RouteResult) bool {
	if result.SuspectedTSPU || strings.EqualFold(strings.TrimSpace(result.Status), "SUSPECTED_TSPU") {
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
	if decision.CandidateInventoryHash == "" || decision.CandidateInventoryHash != plan.InventoryHash {
		return DomainCheck{}, false
	}
	out := DomainCheck{
		Domain: profile.domain, ETLDPlusOne: profile.base, Service: decision.Service,
		Category: decision.Category, TSPUStatus: decision.TSPUStatus, Cached: true,
		Status: decision.Status, Reason: decision.Reason, Confidence: decision.Confidence,
		VerificationState: "verified", VerificationDurationMS: decision.VerificationDurationMS,
		ClassificationState: decision.ClassificationState, ClassificationReason: decision.ClassificationReason,
		CandidateInventoryHash: decision.CandidateInventoryHash,
		Results:                decision.Results, CheckedAt: decision.CheckedAt, ExpiresAt: decision.ExpiresAt,
	}
	out.ClassificationConfidence, out.ClassificationSource, out.ClassificationEvidence = classificationMetadata(profile, tspu.Match{Status: plan.TSPUStatus})
	// Persisted classification evidence is independent from route-decision
	// confidence. Keep the derived legacy value only for old cache records.
	if decision.ClassificationConfidence > 0 || decision.ClassificationSource != "" || decision.ClassificationEvidence != "" {
		out.ClassificationConfidence = decision.ClassificationConfidence
		out.ClassificationSource = decision.ClassificationSource
		out.ClassificationEvidence = decision.ClassificationEvidence
	}
	if strings.EqualFold(strings.TrimSpace(decision.Status), "NO_SAFE_ROUTE") {
		if !validCachedNoSafeRoute(decision, plan) {
			return DomainCheck{}, false
		}
		out.VerificationState = "terminal_no_safe_route"
		return out, true
	}
	if decision.SelectedRoute == "" {
		return out, false
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
		if result.Route == decision.SelectedRoute && result.RouteType == decision.SelectedType && result.AdapterRevision == activeRevision && selectionEvidence(result) {
			selected := result
			out.Selected = &selected
			return out, true
		}
	}
	return DomainCheck{}, false
}

// validCachedNoSafeRoute keeps terminal exhaustion cache entries fail-closed.
// A missing, in-progress, malformed, or foreign candidate result must never be
// treated as proof that no safe route exists.  The active revision and
// inventory checks are performed by cachedCheck before this helper runs.
func validCachedNoSafeRoute(decision domaincache.Decision, plan CandidatePlan) bool {
	if decision.SelectedRoute != "" || decision.Reason != "no_verified_policy_allowed_route" || len(decision.Results) == 0 {
		return false
	}
	for _, result := range decision.Results {
		if !probeResultTerminal(result) {
			return false
		}
		matched := false
		for _, candidate := range plan.Candidates {
			if candidate.Tag == result.Route && candidate.Type == result.RouteType {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func optionNow(opts Options) time.Time {
	if opts.Now != nil {
		return opts.Now().UTC()
	}
	return time.Now().UTC()
}

func decisionConfidence(check DomainCheck, _ tspu.Match) float64 {
	if check.Selected == nil {
		return 0
	}
	// Route selection is binary: a candidate is selected only after the full
	// success contract (route OK, service OK and PathVerified) has passed.
	// TSPU source confidence is classification metadata and must not dilute or
	// inflate the verification state of the selected route.
	return 1
}

func classificationMetadata(profile serviceProfile, match tspu.Match) (float64, string, string) {
	if profile.override != nil {
		return 1, "explicit_override", "user policy override"
	}
	if !profile.unknown {
		if seed := strings.TrimSpace(profile.service.ClassificationSeed); seed != "" {
			return 0, "configured_seed", strings.ToLower(seed)
		}
		return 1, "configured_service", "configured service classification"
	}
	confidence := match.Confidence
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}
	source := strings.TrimSpace(match.Source)
	if source == "" {
		source = "none"
	}
	evidence := strings.TrimSpace(match.Evidence)
	if evidence == "" {
		evidence = strings.ToLower(strings.TrimSpace(match.Status))
	}
	return confidence, source, evidence
}

// classifyEvidence keeps service classification separate from route-decision
// confidence.  A configured seed is only a hint; a live regional marker is
// confirmed only when an alternate route demonstrates the same service.
func classifyEvidence(profile serviceProfile, results []probe.RouteResult, tspuStatus string) (string, string) {
	directRegional := false
	directTSPU := false
	alternateFunctional := false
	for _, result := range results {
		if result.RouteType == "direct" {
			directRegional = directRegional || result.RegionalBlock || strings.EqualFold(strings.TrimSpace(result.Status), "REGION_BLOCK")
			directTSPU = directTSPU || result.SuspectedTSPU || strings.EqualFold(strings.TrimSpace(result.Status), "SUSPECTED_TSPU")
			continue
		}
		if selectionEvidence(result) && result.RouteType != "drop" {
			// A differential GEO proof needs a path whose egress is independently
			// known to be outside the denied region. A merely successful HTTP
			// response through an RU/unknown egress is not an alternate proof.
			country := strings.ToUpper(strings.TrimSpace(result.ExternalCountry))
			if result.EgressConsensus && country != "" && country != "RU" {
				alternateFunctional = true
			}
		}
	}
	if directRegional && alternateFunctional {
		return "CONFIRMED_GEO_LOCKED", "direct regional denial plus functional alternate path"
	}
	if directRegional {
		return "SUSPECTED_GEO_LOCKED", "direct regional denial requires differential verification"
	}
	if directTSPU || tspuStatus == "MATCH" || tspuStatus == "STALE_MATCH" {
		if tspuStatus == "MATCH" {
			return "CONFIRMED_TSPU", "fresh TSPU evidence"
		}
		return "SUSPECTED_TSPU", "TSPU/block evidence without regional confirmation"
	}
	if profile.service.ClassificationSeed != "" {
		return "SEEDED_" + strings.ToUpper(strings.TrimSpace(profile.service.ClassificationSeed)), "configured classification seed is not live proof"
	}
	return "UNKNOWN", "no service-specific classification evidence"
}

func currentHealthyRoute(health *probe.HealthTracker) string {
	if health == nil {
		return ""
	}
	for _, route := range health.Snapshot() {
		if route.State == "healthy" && route.Role == "active" {
			return route.RouteTag
		}
	}
	return ""
}

func hashCandidateInventory(candidates []config.Route, service config.Service, policy config.Policy, tspuStatus string, health *probe.HealthTracker) string {
	// Hash the candidate inventory and the service probe/policy contract. This
	// prevents a cached decision from surviving a manifest or eligibility
	// change, while sorting a copy keeps health-derived ordering out of the key.
	copyRoutes := append([]config.Route(nil), candidates...)
	sort.Slice(copyRoutes, func(i, j int) bool {
		if copyRoutes[i].Type != copyRoutes[j].Type {
			return copyRoutes[i].Type < copyRoutes[j].Type
		}
		return copyRoutes[i].Tag < copyRoutes[j].Tag
	})
	// Include only coarse health fields that affect eligibility/scoring.
	// Timestamps, counters and EWMA samples are deliberately excluded so a
	// healthy cache is not invalidated by every successful probe, while a
	// degraded/unhealthy transition cannot leave a stale route decision active.
	type healthKey struct {
		RouteTag   string `json:"route_tag"`
		State      string `json:"state"`
		Role       string `json:"role"`
		LastStatus string `json:"last_status,omitempty"`
	}
	var healthKeys []healthKey
	if health != nil {
		for _, item := range health.Snapshot() {
			healthKeys = append(healthKeys, healthKey{
				RouteTag: item.RouteTag, State: item.State, Role: item.Role,
				LastStatus: item.LastStatus,
			})
		}
		sort.Slice(healthKeys, func(i, j int) bool { return healthKeys[i].RouteTag < healthKeys[j].RouteTag })
	}
	raw, err := json.Marshal(struct {
		Routes     []config.Route `json:"routes"`
		Service    config.Service `json:"service"`
		Policy     config.Policy  `json:"policy"`
		TSPUStatus string         `json:"tspu_status"`
		Health     []healthKey    `json:"health,omitempty"`
	}{Routes: copyRoutes, Service: service, Policy: policy, TSPUStatus: tspuStatus, Health: healthKeys})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// initialUnknownPolicy describes only the bounded treatment of the first
// connection while a passive DNS observation is being classified. It is not a
// route winner and must not trigger a topology/apply operation.
func initialUnknownPolicy(policy config.Policy) string {
	switch strings.ToLower(strings.TrimSpace(policy.UnknownDomainFirstPath)) {
	case "vless", "privacy_first":
		return "privacy_first"
	case "drop", "fail_closed":
		return "fail_closed"
	default:
		return "balanced"
	}
}

func unknownExpectedCodes() []int {
	codes := make([]int, 0, 200)
	for code := 200; code < 400; code++ {
		codes = append(codes, code)
	}
	return codes
}
