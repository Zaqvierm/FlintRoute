package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/health"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
	"router-policy/internal/state"
	"router-policy/internal/zapret"
)

const (
	adaptiveProbeBucket = "zapret_probe"
	adaptiveProbeKey    = "runtime_v1"
)

var errAdaptiveProbeBusy = errors.New("adaptive probe skipped because another transaction is active")

type persistedAdaptiveProbeRuntime struct {
	Version       int                        `json:"version"`
	CatalogDigest string                     `json:"catalog_digest"`
	Observations  []zapret.ProbeObservation  `json:"observations"`
	Scheduler     zapret.ProbeSchedulerState `json:"scheduler"`
}

type adaptiveFamilyProbeEngine interface {
	ProbeRouteFamily(context.Context, *config.Config, string, string, config.Service, config.Route, string) probe.RouteResult
}

type adaptiveProbeTarget struct {
	ServiceName string
	Domain      string
	Service     config.Service
	Route       config.Route
}

type adaptiveProbeRuntimeStatus struct {
	Enabled            bool                    `json:"enabled"`
	Status             string                  `json:"status"`
	Reason             string                  `json:"reason,omitempty"`
	NetworkFingerprint string                  `json:"network_fingerprint,omitempty"`
	BudgetUsed         int                     `json:"budget_used"`
	BudgetLimit        int                     `json:"budget_limit"`
	InFlight           int                     `json:"in_flight"`
	Rankings           []zapret.CandidateScore `json:"rankings"`
}

func adaptiveCatalogDigest(cfg *config.Config, profiles *zapret.Catalog, bundles *zapret.BundleCatalog) (string, error) {
	if cfg == nil || profiles == nil || bundles == nil {
		return "", errors.New("adaptive catalog digest requires complete inputs")
	}
	type profilePin struct {
		ID              string `json:"id"`
		Provider        string `json:"provider"`
		ProviderVersion string `json:"provider_version"`
		BinaryDigest    string `json:"binary_digest"`
		StrategyDigest  string `json:"strategy_digest"`
	}
	type bundlePin struct {
		ID       string       `json:"id"`
		Digest   string       `json:"digest"`
		Profiles []profilePin `json:"profiles"`
	}
	assignments := append([]config.ZapretProfileAssignment(nil), cfg.Zapret.AdaptiveAssignments...)
	sort.Slice(assignments, func(i, j int) bool { return assignments[i].BundleID < assignments[j].BundleID })
	pins := make([]bundlePin, 0, len(assignments))
	seen := make(map[string]bool, len(assignments))
	for _, assignment := range assignments {
		if seen[assignment.BundleID] {
			continue
		}
		seen[assignment.BundleID] = true
		bundle, ok := bundles.Lookup(assignment.BundleID)
		if !ok {
			return "", fmt.Errorf("adaptive bundle %s is absent from the catalog", assignment.BundleID)
		}
		pin := bundlePin{ID: bundle.ID, Digest: bundle.Digest}
		for _, profileID := range bundle.AllowedProfiles {
			profile, ok := profiles.Lookup(profileID)
			if !ok {
				return "", fmt.Errorf("adaptive profile %s is absent from the catalog", profileID)
			}
			pin.Profiles = append(pin.Profiles, profilePin{ID: profile.ID, Provider: profile.Provider, ProviderVersion: profile.ProviderVersion, BinaryDigest: profile.BinaryDigest, StrategyDigest: profile.StrategyDigest})
		}
		pins = append(pins, pin)
	}
	raw, err := json.Marshal(pins)
	if err != nil {
		return "", err
	}
	return zapret.Digest(raw), nil
}

func restoreAdaptiveProbeRuntime(runtime *adaptiveRuntime, now time.Time) error {
	if runtime == nil || runtime.store == nil || runtime.ranker == nil || runtime.scheduler == nil {
		return errors.New("adaptive probe runtime is incomplete")
	}
	var persisted persistedAdaptiveProbeRuntime
	if err := runtime.store.LoadJSON(adaptiveProbeBucket, adaptiveProbeKey, &persisted); err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("load adaptive probe runtime: %w", err)
	}
	if persisted.Version != 1 || persisted.CatalogDigest != runtime.catalogDigest {
		return nil
	}
	if err := runtime.ranker.Restore(persisted.Observations, now); err != nil {
		return fmt.Errorf("restore adaptive observations: %w", err)
	}
	if err := runtime.scheduler.Restore(persisted.Scheduler, now); err != nil {
		return fmt.Errorf("restore adaptive scheduler: %w", err)
	}
	return nil
}

func persistAdaptiveProbeRuntime(runtime *adaptiveRuntime, now time.Time) error {
	observations, err := runtime.ranker.Observations(now)
	if err != nil {
		return err
	}
	scheduler, err := runtime.scheduler.Snapshot(now)
	if err != nil {
		return err
	}
	return runtime.store.SaveJSON(adaptiveProbeBucket, adaptiveProbeKey, persistedAdaptiveProbeRuntime{
		Version: 1, CatalogDigest: runtime.catalogDigest, Observations: observations, Scheduler: scheduler,
	})
}

func (s *Server) handleAdaptiveZapretRuntime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	now := time.Now().UTC()
	runtime := s.currentAdaptiveRuntime()
	if runtime == nil {
		writeData(w, r, adaptiveProbeRuntimeStatus{Enabled: false, Status: "NOT_CONFIGURED"})
		return
	}
	runtime.probeMu.Lock()
	defer runtime.probeMu.Unlock()
	active := s.currentConfig()
	fingerprint, err := s.adaptiveNetworkFingerprint(active, runtime, now)
	if err != nil {
		used, limit, inFlight := runtime.scheduler.Budget(now)
		writeData(w, r, adaptiveProbeRuntimeStatus{Enabled: true, Status: "UNVERIFIED", Reason: "network_fingerprint_unverified", BudgetUsed: used, BudgetLimit: limit, InFlight: inFlight})
		return
	}
	status := adaptiveProbeRuntimeStatus{Enabled: true, Status: "OK", NetworkFingerprint: fingerprint}
	status.BudgetUsed, status.BudgetLimit, status.InFlight = runtime.scheduler.Budget(now)
	assignments := append([]config.ZapretProfileAssignment(nil), active.Zapret.AdaptiveAssignments...)
	sort.Slice(assignments, func(i, j int) bool { return assignments[i].BundleID < assignments[j].BundleID })
	for _, assignment := range assignments {
		bundle, ok := runtime.bundles.Lookup(assignment.BundleID)
		if !ok {
			continue
		}
		for _, protocol := range bundle.Protocols {
			for _, family := range bundle.IPFamilies {
				key := zapret.DecisionKey{BundleID: bundle.ID, Transport: protocol.Transport, Port: protocol.Port, IPFamily: family, NetworkFingerprint: fingerprint}
				if _, err := selectAdaptiveProbeTarget(active, runtime, bundle, key); err != nil {
					continue
				}
				ranking, err := runtime.ranker.Rank(key, nil, now)
				if err == nil {
					status.Rankings = append(status.Rankings, ranking...)
				}
			}
		}
	}
	writeData(w, r, status)
}

func (s *Server) adaptiveNetworkFingerprint(active *config.Config, runtime *adaptiveRuntime, now time.Time) (string, error) {
	reporter, ok := s.provider.(platform.NetworkDiagnosticsProvider)
	if !ok {
		return "", errors.New("network diagnostics provider is unavailable")
	}
	diagnostics := reporter.NetworkDiagnostics(active)
	if diagnostics.Status != "VERIFIED" || diagnostics.Simulation || diagnostics.CollectedAt.IsZero() || diagnostics.ExpiresAt.IsZero() || now.After(diagnostics.ExpiresAt) {
		return "", errors.New("verified fresh hardware network diagnostics are required")
	}
	resolvers := append([]string(nil), diagnostics.DNSResolvers...)
	sort.Strings(resolvers)
	overview := s.provider.Overview(active)
	externalIPv4Hash, _ := overview["external_ipv4_hash"].(string)
	stable := struct {
		Source               string   `json:"source"`
		WANInterface         string   `json:"wan_interface"`
		IPv4Gateway          string   `json:"ipv4_gateway"`
		IPv6Gateway          string   `json:"ipv6_gateway"`
		IPv6Available        bool     `json:"ipv6_available"`
		DNSResolvers         []string `json:"dns_resolvers"`
		TransparentProxyMode string   `json:"transparent_proxy_mode"`
		FlowOffloadingStatus string   `json:"flow_offloading_status"`
		SoftwareFlowOffload  bool     `json:"software_flow_offloading"`
		HardwareFlowOffload  bool     `json:"hardware_flow_offloading"`
		ExternalIPv4Hash     string   `json:"external_ipv4_hash"`
		CatalogDigest        string   `json:"catalog_digest"`
	}{
		Source: diagnostics.Source, WANInterface: diagnostics.WANInterface,
		IPv4Gateway: diagnostics.IPv4Gateway, IPv6Gateway: diagnostics.IPv6Gateway,
		IPv6Available: diagnostics.IPv6Available, DNSResolvers: resolvers,
		TransparentProxyMode: diagnostics.TransparentProxyMode,
		FlowOffloadingStatus: diagnostics.FlowOffloadingStatus,
		SoftwareFlowOffload:  diagnostics.SoftwareFlowOffload,
		HardwareFlowOffload:  diagnostics.HardwareFlowOffload,
		ExternalIPv4Hash:     externalIPv4Hash,
		CatalogDigest:        runtime.catalogDigest,
	}
	raw, err := json.Marshal(stable)
	if err != nil {
		return "", err
	}
	return zapret.Digest(raw), nil
}

func (s *Server) runAdaptiveZapretCycle(ctx context.Context, active *config.Config, engine health.ProbeEngine, now time.Time) {
	runtime := s.currentAdaptiveRuntime()
	if runtime == nil || active == nil || engine == nil {
		return
	}
	runtime.probeMu.Lock()
	defer runtime.probeMu.Unlock()
	fingerprint, err := s.adaptiveNetworkFingerprint(active, runtime, now)
	if err != nil {
		s.publishEvent(Event{Type: "zapret.adaptive_probe", Severity: "warning", ReasonCode: "network_fingerprint_unverified", Details: map[string]any{"error": err.Error()}})
		return
	}
	assignments := append([]config.ZapretProfileAssignment(nil), active.Zapret.AdaptiveAssignments...)
	sort.Slice(assignments, func(i, j int) bool { return assignments[i].BundleID < assignments[j].BundleID })
	for _, assignment := range assignments {
		bundle, ok := runtime.bundles.Lookup(assignment.BundleID)
		if !ok {
			continue
		}
		for _, protocol := range bundle.Protocols {
			for _, family := range bundle.IPFamilies {
				key := zapret.DecisionKey{BundleID: bundle.ID, Transport: protocol.Transport, Port: protocol.Port, IPFamily: family, NetworkFingerprint: fingerprint}
				if _, targetErr := selectAdaptiveProbeTarget(active, runtime, bundle, key); targetErr != nil {
					continue
				}
				ranking, rankErr := runtime.ranker.Rank(key, nil, now)
				if rankErr != nil {
					continue
				}
				lease, due, scheduleErr := runtime.scheduler.Next(key, assignment.ProfileID, ranking, now)
				if scheduleErr != nil || !due {
					continue
				}
				s.runScheduledAdaptiveProbe(ctx, active, engine, runtime, bundle, assignment.ProfileID, lease, now)
				return
			}
		}
	}
}

func (s *Server) runScheduledAdaptiveProbe(ctx context.Context, active *config.Config, engine health.ProbeEngine, runtime *adaptiveRuntime, bundle zapret.ServiceBundle, activeProfile string, lease zapret.ScheduledProbe, now time.Time) {
	finishedAt := now
	completeLease := true
	defer func() {
		if finishedAt.Before(lease.ScheduledAt) {
			finishedAt = lease.ScheduledAt
		}
		if finishedAt.After(lease.Deadline) {
			finishedAt = lease.Deadline
		}
		if completeLease {
			_ = runtime.scheduler.Complete(lease.Token, finishedAt)
		} else {
			_ = runtime.scheduler.Cancel(lease.Token)
		}
		_ = persistAdaptiveProbeRuntime(runtime, finishedAt)
	}()

	var result probe.RouteResult
	var probeErr error
	if lease.ProfileID == activeProfile {
		result, probeErr = s.probeAdaptiveTarget(ctx, active, engine, runtime, bundle, lease.Key)
	} else {
		result, probeErr = s.calibrateAdaptiveCandidate(ctx, active, runtime, bundle, lease)
	}
	finishedAt = time.Now().UTC()
	if finishedAt.Before(lease.ScheduledAt) {
		finishedAt = lease.ScheduledAt
	}
	if finishedAt.After(lease.Deadline) {
		finishedAt = lease.Deadline
	}
	if errors.Is(probeErr, errAdaptiveProbeBusy) {
		completeLease = false
		return
	}
	observation := adaptiveObservation(lease, result, probeErr, finishedAt)
	score, err := runtime.ranker.Observe(observation)
	if err != nil {
		s.publishEvent(Event{Type: "zapret.adaptive_probe", Severity: "error", ReasonCode: "adaptive_observation_rejected", Details: map[string]any{"bundle_id": lease.Key.BundleID, "profile_id": lease.ProfileID, "error": err.Error()}})
		return
	}
	if !observation.Success && lease.ProfileID == activeProfile {
		_ = runtime.scheduler.RequestConfirmation(lease.Key, activeProfile, finishedAt)
	}
	s.publishEvent(Event{Type: "zapret.adaptive_probe", Severity: adaptiveProbeSeverity(observation), ReasonCode: "adaptive_probe_completed", Details: map[string]any{
		"bundle_id": lease.Key.BundleID, "profile_id": lease.ProfileID, "class": lease.Class,
		"success": observation.Success, "path_verified": observation.PathVerified,
		"attempts": score.Attempts, "production_ready": score.ProductionReady,
	}})
	ranking, err := runtime.ranker.Rank(lease.Key, nil, finishedAt)
	if err != nil {
		return
	}
	_, _ = s.evaluateAdaptiveZapret(context.WithoutCancel(ctx), adaptiveEvaluateRequest{Key: lease.Key, Ranking: ranking}, finishedAt)
}

func (s *Server) probeAdaptiveTarget(ctx context.Context, cfg *config.Config, engine health.ProbeEngine, runtime *adaptiveRuntime, bundle zapret.ServiceBundle, key zapret.DecisionKey) (probe.RouteResult, error) {
	target, err := selectAdaptiveProbeTarget(cfg, runtime, bundle, key)
	if err != nil {
		return probe.RouteResult{}, err
	}
	familyEngine, ok := engine.(adaptiveFamilyProbeEngine)
	if !ok {
		return probe.RouteResult{}, errors.New("probe engine cannot bind an address family")
	}
	result := familyEngine.ProbeRouteFamily(ctx, cfg, target.Domain, target.ServiceName, target.Service, target.Route, key.IPFamily)
	if err := s.store.StoreProbeResult(result); err != nil {
		return result, fmt.Errorf("persist adaptive probe result: %w", err)
	}
	return result, nil
}

func (s *Server) calibrateAdaptiveCandidate(ctx context.Context, active *config.Config, runtime *adaptiveRuntime, bundle zapret.ServiceBundle, lease zapret.ScheduledProbe) (probe.RouteResult, error) {
	updated, err := replaceBundleProfile(active.Zapret.AdaptiveAssignments, bundle.ID, lease.ProfileID)
	if err != nil {
		return probe.RouteResult{}, err
	}
	s.mu.Lock()
	baseVersion := s.configVersion
	s.mu.Unlock()
	change, err := s.createDraftChange("Calibrate Zapret service profile", "Scheduled bounded profile calibration", baseVersion, []ChangeOp{{Type: "update", Path: "/zapret/adaptive_assignments", Value: updated}}, "adaptive-scheduler")
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			return probe.RouteResult{}, errAdaptiveProbeBusy
		}
		return probe.RouteResult{}, err
	}
	change, failure := s.validateChangeSet(change)
	if failure == nil {
		change, failure = s.applyChangeSet(ctx, change)
	}
	if failure != nil {
		if failure.Status == 409 {
			return probe.RouteResult{}, errAdaptiveProbeBusy
		}
		return probe.RouteResult{}, fmt.Errorf("candidate apply failed: %s", failure.Code)
	}
	if change.State != "awaiting_confirmation" {
		return probe.RouteResult{}, errors.New("adaptive calibration did not reach confirmation")
	}
	candidate, err := cloneConfigWithAdaptiveAssignments(active, updated)
	if err != nil {
		_, _ = s.rollbackChangeSet(context.WithoutCancel(ctx), change, false)
		return probe.RouteResult{}, err
	}
	result, probeErr := s.probeAdaptiveTarget(ctx, candidate, s.probeEngineFactory(candidate), runtime, bundle, lease.Key)
	rolled, rollbackFailure := s.rollbackChangeSet(context.WithoutCancel(ctx), change, false)
	if rollbackFailure != nil || rolled.State != "rolled_back" {
		return result, errors.New("adaptive calibration rollback failed")
	}
	return result, probeErr
}

func cloneConfigWithAdaptiveAssignments(active *config.Config, assignments []config.ZapretProfileAssignment) (*config.Config, error) {
	raw, err := json.Marshal(active)
	if err != nil {
		return nil, err
	}
	var cloned config.Config
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return nil, err
	}
	cloned.Zapret.AdaptiveAssignments = append([]config.ZapretProfileAssignment(nil), assignments...)
	return &cloned, cloned.Validate()
}

func selectAdaptiveProbeTarget(cfg *config.Config, runtime *adaptiveRuntime, bundle zapret.ServiceBundle, key zapret.DecisionKey) (adaptiveProbeTarget, error) {
	if key.Transport != "tcp" {
		return adaptiveProbeTarget{}, errors.New("production adaptive probe does not support this transport")
	}
	names := make([]string, 0, len(cfg.Services))
	for name := range cfg.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		service := cfg.Services[name]
		owned := false
		for _, domain := range service.Domains {
			owner, ok := runtime.bundles.LookupDomain(domain)
			if ok && owner.ID == bundle.ID {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}
		checks := make([]config.ProbeCheck, 0, len(service.ProbeURLs))
		domain := ""
		for _, check := range service.ProbeURLs {
			parsed, err := url.Parse(check.URL)
			if err != nil || protocolPort(parsed) != key.Port {
				continue
			}
			owner, ok := runtime.bundles.LookupDomain(parsed.Hostname())
			if !ok || owner.ID != bundle.ID {
				continue
			}
			checks = append(checks, check)
			if domain == "" {
				domain = parsed.Hostname()
			}
		}
		if len(checks) == 0 {
			continue
		}
		service.ProbeURLs = checks
		for _, route := range cfg.RoutesByType("zapret") {
			if route.Enabled() && config.PathAllowed(service, route, cfg.Policy) {
				return adaptiveProbeTarget{ServiceName: name, Domain: domain, Service: service, Route: route}, nil
			}
		}
	}
	return adaptiveProbeTarget{}, errors.New("no protocol-specific service probe is configured for the adaptive bundle")
}

func protocolPort(parsed *url.URL) uint16 {
	port := parsed.Port()
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return 0
		}
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return 0
	}
	return uint16(value)
}

func adaptiveObservation(lease zapret.ScheduledProbe, result probe.RouteResult, probeErr error, observedAt time.Time) zapret.ProbeObservation {
	requiredSeen := false
	requiredPassed := true
	protocolProof := false
	for _, check := range result.Checks {
		if check.Required {
			requiredSeen = true
			if check.Status != "OK" {
				requiredPassed = false
			}
		}
		familyMatches := lease.Key.IPFamily == "ipv4" && check.AddressFamily == "ipv4" || lease.Key.IPFamily == "ipv6" && check.AddressFamily == "ipv6"
		if check.Transport == lease.Key.Transport && check.ConnectedPort == int(lease.Key.Port) && familyMatches {
			protocolProof = true
		}
	}
	pathVerified := result.PathVerified && protocolProof && !result.Simulation
	safety := probeErr == nil && !result.RegionalBlock && !result.SuspectedTSPU && pathVerified
	requiredPassed = probeErr == nil && requiredSeen && requiredPassed && result.ServiceOK
	success := result.Status == "OK" && safety && requiredPassed
	hardFailure := result.Simulation || probeErr != nil && !errors.Is(probeErr, errAdaptiveProbeBusy) || result.Status == "UNVERIFIED"
	latency := time.Duration(result.LatencyMS) * time.Millisecond
	return zapret.ProbeObservation{
		Key: lease.Key, ProfileID: lease.ProfileID, ObservedAt: observedAt,
		Success: success, SafetyGate: safety, RequiredChecksPassed: requiredPassed,
		PathVerified: pathVerified, HardFailure: hardFailure, Latency: latency,
	}
}

func adaptiveProbeSeverity(observation zapret.ProbeObservation) string {
	if observation.HardFailure {
		return "error"
	}
	if !observation.Success {
		return "warning"
	}
	return "info"
}
