package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"router-policy/internal/adapter"
	"router-policy/internal/auth"
	"router-policy/internal/config"
	"router-policy/internal/discovery"
	"router-policy/internal/domaincache"
	"router-policy/internal/health"
	"router-policy/internal/managementproof"
	"router-policy/internal/planner"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
	"router-policy/internal/secureid"
	"router-policy/internal/security"
	"router-policy/internal/state"
	"router-policy/internal/traffic"
	"router-policy/internal/tspu"
	"router-policy/internal/vpnsub"
	"router-policy/internal/web"
)

var secureRandomHex = secureid.Hex

type Options struct {
	Auth                   *auth.Store
	Provider               platform.Provider
	State                  *state.Store
	ProductionAdapter      adapter.Interface
	SubscriptionPreparer   SubscriptionPreparer
	ProbeEngineFactory     func(*config.Config) health.ProbeEngine
	TSPURefresh            TSPURefreshFunc
	DNSObservationPath     string
	Development            bool
	ManagementProofs       *managementproof.Manager
	RequireManagementProof bool
}

type SubscriptionPreparer interface {
	Prepare(context.Context, *config.Config) (vpnsub.PreparedBundle, error)
}

type TSPURefreshFunc func(context.Context, *config.Config, time.Time) (tspu.Cache, error)

type tspuDelayFunc func(time.Duration, int, bool) time.Duration

type actionLockEntry struct {
	mu   sync.Mutex
	refs int
}

type Server struct {
	cfg                    *config.Config
	auth                   *auth.Store
	provider               platform.Provider
	store                  *state.Store
	adapter                adapter.Interface
	subscriptionPreparer   SubscriptionPreparer
	probeEngineFactory     func(*config.Config) health.ProbeEngine
	tspuRefresh            TSPURefreshFunc
	tspuDelay              tspuDelayFunc
	healthTracker          *probe.HealthTracker
	domainDecisions        *domaincache.Manager
	dnsObservationPath     string
	development            bool
	broker                 *EventBroker
	mux                    *http.ServeMux
	mu                     sync.Mutex
	changes                map[string]ChangeSet
	actionLocks            map[string]*actionLockEntry
	transactionMu          sync.Mutex
	subscriptionMu         sync.Mutex
	timers                 map[string]*time.Timer
	timerWG                sync.WaitGroup
	closing                bool
	activeConfig           *config.Config
	activeRevision         string
	configVersion          int64
	recovery               recoveryStatus
	hideSensitive          bool
	adaptiveZapret         *adaptiveRuntime
	managementProofs       *managementproof.Manager
	requireManagementProof bool
	schedulerOnce          sync.Once
	schedulerCancel        context.CancelFunc
	schedulerWG            sync.WaitGroup
	closeOnce              sync.Once
	closeErr               error
}

func NewServerWithOptions(cfg *config.Config, opts Options) (*Server, error) {
	if opts.ProductionAdapter == nil {
		return nil, fmt.Errorf("ProductionAdapter dependency is required")
	}
	var err error
	requireManagementProof := opts.RequireManagementProof
	if _, ok := opts.ProductionAdapter.(*adapter.OpenWrt); ok {
		requireManagementProof = true
	}
	managementProofs := opts.ManagementProofs
	if requireManagementProof && managementProofs == nil {
		managementProofs, err = managementproof.New(cfg.Storage.StateDir, cfg.Storage.RuntimeDir, managementproof.Options{})
		if err != nil {
			return nil, fmt.Errorf("initialize management proof service: %w", err)
		}
	}
	authStore := opts.Auth
	if authStore == nil {
		authStore, err = auth.Open(cfg)
		if err != nil {
			return nil, err
		}
	}
	provider := opts.Provider
	if provider == nil {
		provider = platform.NewOpenWrtProvider()
	}
	stateStore := opts.State
	if stateStore == nil {
		stateStore, err = state.Open(cfg)
		if err != nil {
			return nil, err
		}
	}
	if _, err := ensureBaselineRevision(stateStore, cfg, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := stateStore.Maintain(time.Now().UTC()); err != nil {
		return nil, err
	}
	changes, err := loadPersistedChangeSets(stateStore)
	if err != nil {
		return nil, err
	}
	configVersion, err := stateStore.GetInt64("config_version", 1)
	if err != nil {
		return nil, err
	}
	activeConfig, activeRevision, err := loadActiveConfig(stateStore, cfg)
	if err != nil {
		return nil, err
	}
	persistedHealth, err := stateStore.ListRouteHealth()
	if err != nil {
		return nil, err
	}
	domainDecisions, err := domaincache.New(stateStore, activeConfig.Storage.MaxAutoDomains)
	if err != nil {
		return nil, err
	}
	probeEngineFactory := opts.ProbeEngineFactory
	if probeEngineFactory == nil {
		allowSimulation := opts.Development
		probeEngineFactory = func(active *config.Config) health.ProbeEngine {
			return probe.NewActiveOpenWrtEngine(active, allowSimulation)
		}
	}
	tspuRefresh := opts.TSPURefresh
	if tspuRefresh == nil {
		tspuRefresh = func(ctx context.Context, active *config.Config, now time.Time) (tspu.Cache, error) {
			path := filepath.Join(active.Storage.StateDir, "tspu-cache.json")
			return tspu.RefreshFile(ctx, nil, active, path, now)
		}
	}
	dnsObservationPath := opts.DNSObservationPath
	if dnsObservationPath == "" {
		dnsObservationPath = filepath.Join(activeConfig.Storage.RuntimeDir, "dns-observations.log")
	}
	broker, err := NewEventBroker(512)
	if err != nil {
		_ = stateStore.Close()
		return nil, err
	}
	s := &Server{
		cfg:                    cfg,
		auth:                   authStore,
		provider:               provider,
		store:                  stateStore,
		adapter:                opts.ProductionAdapter,
		subscriptionPreparer:   opts.SubscriptionPreparer,
		probeEngineFactory:     probeEngineFactory,
		tspuRefresh:            tspuRefresh,
		tspuDelay:              randomTSPUDelay,
		healthTracker:          probe.NewHealthTracker(persistedHealth),
		domainDecisions:        domainDecisions,
		dnsObservationPath:     dnsObservationPath,
		development:            opts.Development,
		broker:                 broker,
		mux:                    http.NewServeMux(),
		changes:                changes,
		actionLocks:            map[string]*actionLockEntry{},
		timers:                 map[string]*time.Timer{},
		activeConfig:           activeConfig,
		activeRevision:         activeRevision,
		configVersion:          configVersion,
		hideSensitive:          true,
		managementProofs:       managementProofs,
		requireManagementProof: requireManagementProof,
	}
	s.adaptiveZapret, err = buildAdaptiveRuntime(activeConfig, stateStore)
	if err != nil {
		_ = stateStore.Close()
		return nil, fmt.Errorf("initialize adaptive Zapret: %w", err)
	}
	s.routes()
	if err := s.recoverTransactions(context.Background()); err != nil {
		_ = stateStore.Close()
		return nil, err
	}
	s.adaptiveZapret, err = buildAdaptiveRuntime(s.currentConfig(), stateStore)
	if err != nil {
		_ = stateStore.Close()
		return nil, fmt.Errorf("refresh adaptive Zapret after recovery: %w", err)
	}
	s.recoverCommittedDataplane(context.Background())
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.securityHeaders(s.withRequestID(s.limitBody(s.mux)))
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		cancelScheduler := s.schedulerCancel
		for id := range s.timers {
			s.cancelExpiryLocked(id)
		}
		s.mu.Unlock()
		if cancelScheduler != nil {
			cancelScheduler()
		}
		s.schedulerWG.Wait()
		s.timerWG.Wait()
		if s.store != nil {
			s.closeErr = s.store.Close()
		}
	})
	return s.closeErr
}

func (s *Server) StartScheduler(ctx context.Context) {
	s.schedulerOnce.Do(func() {
		schedulerCtx, cancel := context.WithCancel(ctx)
		s.mu.Lock()
		s.schedulerCancel = cancel
		s.mu.Unlock()

		interval := time.Duration(s.cfg.Policy.HealthCheckIntervalSeconds) * time.Second
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		s.schedulerWG.Add(1)
		go func() {
			defer s.schedulerWG.Done()
			s.runHealthCycle(schedulerCtx)
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			maintenance := time.NewTicker(6 * time.Hour)
			defer maintenance.Stop()
			for {
				select {
				case <-schedulerCtx.Done():
					return
				case <-ticker.C:
					s.runHealthCycle(schedulerCtx)
				case <-maintenance.C:
					if err := s.store.Maintain(time.Now().UTC()); err != nil {
						s.publishEvent(Event{Type: "state.maintenance_failed", Severity: "error", ReasonCode: "bbolt_maintenance_failed", Details: map[string]any{"error": err.Error()}})
					}
				}
			}
		}()
		s.startTSPUScheduler(schedulerCtx)
		s.startDNSDiscovery(schedulerCtx)
	})
}

func (s *Server) startTSPUScheduler(ctx context.Context) {
	s.schedulerWG.Add(1)
	go func() {
		defer s.schedulerWG.Done()
		s.runTSPUScheduler(ctx)
	}()
}

func (s *Server) startDNSDiscovery(ctx context.Context) {
	if !s.currentConfig().Policy.UnknownDomainBackgroundCheck || s.dnsObservationPath == "" {
		return
	}
	s.schedulerWG.Add(1)
	go func() {
		defer s.schedulerWG.Done()
		watcher := discovery.Watcher{
			Path: s.dnsObservationPath,
			Emit: func(observationContext context.Context, observation discovery.Observation) {
				s.discoverDomain(observationContext, observation)
			},
		}
		if err := watcher.Run(ctx); err != nil && ctx.Err() == nil {
			s.publishEvent(Event{Type: "domain.discovery", Severity: "error", ReasonCode: "dns_observation_failed", Details: map[string]any{"error": err.Error()}})
		}
	}()
}

func (s *Server) discoverDomain(ctx context.Context, observation discovery.Observation) {
	active := s.currentConfig()
	if active == nil || active.ServiceForDomain(observation.Domain) != "" {
		return
	}
	s.mu.Lock()
	revision := s.activeRevision
	s.mu.Unlock()
	if revision == "" {
		return
	}
	now := time.Now().UTC()
	match := tspu.Match{Domain: observation.Domain, Status: "UNAVAILABLE"}
	cache, err := tspu.Load(filepath.Join(active.Storage.StateDir, "tspu-cache.json"))
	if err == nil {
		if found, ok := tspu.Find(cache, observation.Domain, now); ok {
			match = found
		} else {
			match = tspu.Match{Domain: observation.Domain, Status: "NO_MATCH"}
		}
	}
	checkCtx, cancel := context.WithTimeout(ctx, time.Duration(maxInt(active.Policy.MaxProbeSeconds, 15))*time.Second)
	defer cancel()
	check, err := planner.CheckDomain(checkCtx, active, observation.Domain, "", planner.Options{
		TSPUResult: match, RouteProber: s.probeEngineFactory(active), HealthTracker: s.healthTracker,
		DecisionCache: s.domainDecisions, ActiveRevision: revision,
	})
	if err != nil {
		s.publishEvent(Event{Type: "route.decision", Severity: "warning", ReasonCode: "automatic_domain_check_failed", Details: map[string]any{"domain": observation.Domain, "error": err.Error()}})
		return
	}
	details := map[string]any{
		"domain": check.Domain, "category": check.Category, "status": check.Status,
		"confidence": check.Confidence, "tspu_status": check.TSPUStatus, "query_type": observation.QueryType,
	}
	if check.Selected != nil {
		details["route"] = check.Selected.Route
		details["route_type"] = check.Selected.RouteType
	}
	s.publishEvent(Event{Type: "route.decision", Severity: "info", ReasonCode: "automatic_domain_classified", Details: details})
	if check.Selected == nil || check.Selected.RouteType == "direct" || check.Selected.RouteType == "drop" {
		return
	}
	if err := s.commitAutomaticDomain(ctx, check); err != nil {
		s.publishEvent(Event{Type: "domain.discovery", Severity: "warning", ReasonCode: "automatic_policy_commit_failed", Details: map[string]any{"domain": check.Domain, "error": err.Error()}})
	}
}

func (s *Server) commitAutomaticDomain(ctx context.Context, check planner.DomainCheck) error {
	service, id, ok := automaticServiceForDecision(check)
	if !ok {
		return nil
	}
	active := s.currentConfig()
	if active.ServiceForDomain(check.Domain) != "" {
		return nil
	}
	s.mu.Lock()
	baseVersion := s.configVersion
	s.mu.Unlock()
	change, err := s.createDraftChange("Add discovered domain policy", "Apply verified automatic route decision", baseVersion, []ChangeOp{{
		Type: "set", Path: "/services/" + escapeJSONPointer(id), Value: service,
	}}, "domain-discovery")
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			return nil
		}
		return err
	}
	change, failure := s.validateChangeSet(change)
	if failure == nil {
		change, failure = s.applyChangeSet(withAutomaticManagementProof(ctx), change)
	}
	if failure == nil && change.State != "awaiting_confirmation" {
		failure = conflict("automatic_apply_unverified", "automatic domain policy did not reach confirmation")
	}
	if failure == nil {
		change, failure = s.confirmChangeSet(ctx, change)
	}
	if failure != nil {
		if change.TransactionID != "" && change.State != "rolled_back" && change.State != "expired" {
			_, _ = s.rollbackChangeSet(context.WithoutCancel(ctx), change, false)
		}
		return errors.New(failure.Code)
	}
	return nil
}

func automaticServiceForDecision(check planner.DomainCheck) (config.Service, string, bool) {
	if check.Selected == nil || check.ETLDPlusOne == "" {
		return config.Service{}, "", false
	}
	category := check.Category
	if category != "GEO_LOCKED" && (check.TSPUStatus == "MATCH" || check.TSPUStatus == "STALE_MATCH" || check.Selected.RouteType == "zapret" || domainCheckSuspectsTSPU(check)) {
		category = "TSPU_RESTRICTED"
	}
	var allowed, forbidden []string
	requireNonRU := false
	switch category {
	case "GEO_LOCKED":
		allowed = []string{"smart_dns", "vless", "drop"}
		forbidden = []string{"direct", "zapret"}
		requireNonRU = true
	case "TSPU_RESTRICTED":
		allowed = []string{"zapret", "smart_dns", "vless", "direct", "drop"}
	default:
		return config.Service{}, "", false
	}
	id := "auto_" + strings.NewReplacer(".", "_", "-", "_").Replace(check.ETLDPlusOne)
	return config.Service{
		Category: category, Domains: []string{check.ETLDPlusOne},
		AllowedPaths: allowed, ForbiddenPaths: forbidden, SelectedRouteTag: check.Selected.Route,
		RequireNonRUEgress: requireNonRU,
		ProbeURLs: []config.ProbeCheck{{
			Name: "automatic-web", URL: "https://" + check.Domain + "/", Required: true,
			ExpectedCodes: []int{200, 204, 301, 302, 303, 307, 308, 401, 403}, BodyMode: "optional",
		}},
	}, id, true
}

func domainCheckSuspectsTSPU(check planner.DomainCheck) bool {
	for _, result := range check.Results {
		if result.SuspectedTSPU {
			return true
		}
	}
	return false
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func (s *Server) runTSPUScheduler(ctx context.Context) {
	failures := 0
	initial := true
	for {
		active := s.tspuSchedulerConfig()
		interval := time.Duration(active.Policy.TSPUListUpdateIntervalSeconds) * time.Second
		if interval <= 0 || len(active.TSPUSources) == 0 {
			failures = 0
			if !waitForScheduler(ctx, 5*time.Minute) {
				return
			}
			continue
		}

		delay := s.tspuDelay(interval, failures, initial)
		if initial {
			delay = tspuInitialDelay(active, interval, time.Now().UTC(), delay)
		}
		initial = false
		if !waitForScheduler(ctx, delay) {
			return
		}
		if err := s.runTSPURefresh(ctx); err != nil {
			failures++
		} else {
			failures = 0
		}
	}
}

func tspuInitialDelay(active *config.Config, interval time.Duration, now time.Time, fallback time.Duration) time.Duration {
	if active == nil || interval <= 0 {
		return fallback
	}
	cache, err := tspu.Load(filepath.Join(active.Storage.StateDir, "tspu-cache.json"))
	if err != nil || !cache.ExpiresAt.After(now) {
		return fallback
	}
	lead := interval / 10
	if lead > 5*time.Minute {
		lead = 5 * time.Minute
	}
	if lead < time.Second {
		lead = time.Second
	}
	delay := cache.ExpiresAt.Sub(now) - lead
	if delay < fallback {
		return fallback
	}
	return delay
}

func (s *Server) runTSPURefresh(ctx context.Context) error {
	active := s.tspuSchedulerConfig()
	refreshCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cache, err := s.tspuRefresh(refreshCtx, active, time.Now().UTC())
	details := map[string]any{
		"entries": len(cache.Entries), "fresh_sources": cache.FreshSources,
	}
	if err != nil {
		details["error"] = err.Error()
		s.publishEvent(Event{Type: "tspu.cache", Severity: "warning", ReasonCode: "tspu_cache_refresh_failed", Details: details})
		return err
	}
	details["sha256"] = cache.SHA256
	details["previous_sha256"] = cache.PreviousSHA256
	details["expires_at"] = cache.ExpiresAt
	s.publishEvent(Event{Type: "tspu.cache", Severity: "info", ReasonCode: "tspu_cache_refresh_completed", Details: details})
	return nil
}

func (s *Server) tspuSchedulerConfig() *config.Config {
	active := s.currentConfig()
	if active == nil || len(active.TSPUSources) > 0 || s.cfg == nil || len(s.cfg.TSPUSources) == 0 {
		return active
	}
	merged := *active
	merged.TSPUSources = append([]config.TSPUSource(nil), s.cfg.TSPUSources...)
	return &merged
}

func waitForScheduler(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		delay = time.Millisecond
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func randomTSPUDelay(interval time.Duration, failures int, initial bool) time.Duration {
	base := tspuBaseDelay(interval, failures, initial)
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return base
	}
	sample := uint16(random[0])<<8 | uint16(random[1])
	return jitterTSPUDelay(base, sample)
}

func tspuBaseDelay(interval time.Duration, failures int, initial bool) time.Duration {
	if interval <= 0 {
		return 5 * time.Minute
	}
	if initial {
		if interval < 30*time.Second {
			return interval
		}
		return 30 * time.Second
	}
	if failures <= 0 {
		return interval
	}
	retry := time.Minute
	for attempt := 1; attempt < failures && retry < time.Hour; attempt++ {
		retry *= 2
	}
	if retry > time.Hour {
		retry = time.Hour
	}
	if retry > interval {
		return interval
	}
	return retry
}

func jitterTSPUDelay(base time.Duration, sample uint16) time.Duration {
	if base <= 0 {
		return time.Millisecond
	}
	span := base / 10
	offset := time.Duration(float64(span) * (float64(sample)/float64(^uint16(0))*2 - 1))
	delay := base + offset
	if delay < time.Millisecond {
		return time.Millisecond
	}
	return delay
}

func (s *Server) runHealthCycle(ctx context.Context) {
	active := s.currentConfig()
	engine := s.probeEngineFactory(active)
	now := time.Now().UTC()
	service := health.Service{
		Tracker: s.healthTracker, Store: s.store,
		Parallelism: active.Policy.ParallelServerChecks, MaxControlServices: 3,
	}
	cycle, err := service.RunCycle(ctx, active, engine, now)
	severity := "info"
	reason := "vless_health_cycle_completed"
	if err != nil {
		severity = "error"
		reason = "vless_health_cycle_failed"
	} else if cycle.Status == "UNVERIFIED" {
		severity = "warning"
		reason = "vless_health_unverified"
	} else if cycle.Status == "DEGRADED" {
		severity = "warning"
		reason = "vless_health_degraded"
	}
	details := map[string]any{
		"status": cycle.Status, "routes_checked": cycle.RoutesChecked, "probe_count": cycle.ProbeCount,
		"failures": cycle.Failures, "selected_route": cycle.SelectedTag,
	}
	if err != nil {
		details["error"] = err.Error()
	}
	s.publishEvent(Event{Type: "route.health", Severity: severity, ReasonCode: reason, Details: details})
	s.runAdaptiveZapretCycle(ctx, active, engine, now)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/v1/auth/setup", s.handleSetup)
	s.mux.HandleFunc("/api/v1/auth/logout", s.requireRole(auth.RoleViewer, s.handleLogout))
	s.mux.HandleFunc("/api/v1/auth/me", s.requireRole(auth.RoleViewer, s.handleMe))
	s.mux.HandleFunc("/api/v1/overview", s.requireRole(auth.RoleViewer, s.handleOverview))
	s.mux.HandleFunc("/api/v1/topology", s.requireRole(auth.RoleViewer, s.handleTopology))
	s.mux.HandleFunc("/api/v1/devices", s.requireRole(auth.RoleViewer, s.handleDevices))
	s.mux.HandleFunc("/api/v1/services", s.requireRole(auth.RoleViewer, s.handleServices))
	s.mux.HandleFunc("/api/v1/services/classify", s.requireRole(auth.RoleAdministrator, s.handleServiceClassify))
	s.mux.HandleFunc("/api/v1/domains", s.requireRole(auth.RoleViewer, s.handleDomains))
	s.mux.HandleFunc("/api/v1/policies", s.requireRole(auth.RoleViewer, s.handlePolicies))
	s.mux.HandleFunc("/api/v1/routes", s.requireRole(auth.RoleViewer, s.handleRoutes))
	s.mux.HandleFunc("/api/v1/traffic", s.requireRole(auth.RoleViewer, s.handleTraffic))
	s.mux.HandleFunc("/api/v1/route-health", s.requireRole(auth.RoleViewer, s.handleRouteHealth))
	s.mux.HandleFunc("/api/v1/proxies", s.requireRole(auth.RoleViewer, s.handleProxies))
	s.mux.HandleFunc("/api/v1/xray/subscription/secret", s.requireRole(auth.RoleAdministrator, s.handleXraySubscriptionSecret))
	s.mux.HandleFunc("/api/v1/xray/subscription/prepare", s.requireRole(auth.RoleAdministrator, s.handleXraySubscriptionPrepare))
	s.mux.HandleFunc("/api/v1/smart-dns", s.requireRole(auth.RoleViewer, s.handleSmartDNS))
	s.mux.HandleFunc("/api/v1/smart-dns/configure", s.requireRole(auth.RoleAdministrator, s.handleSmartDNSConfigure))
	s.mux.HandleFunc("/api/v1/zapret", s.requireRole(auth.RoleViewer, s.handleZapret))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/runtime", s.requireRole(auth.RoleViewer, s.handleAdaptiveZapretRuntime))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/evaluate", s.requireRole(auth.RoleAdministrator, s.handleAdaptiveZapretEvaluate))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/state", s.requireRole(auth.RoleAdministrator, s.handleAdaptiveZapretState))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/pin", s.requireRole(auth.RoleAdministrator, s.handleAdaptiveZapretPin))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/unpin", s.requireRole(auth.RoleAdministrator, s.handleAdaptiveZapretUnpin))
	s.mux.HandleFunc("/api/v1/telegram", s.requireRole(auth.RoleViewer, s.handleTelegram))
	s.mux.HandleFunc("/api/v1/diagnostics", s.requireRole(auth.RoleDiagnostician, s.handleDiagnostics))
	s.mux.HandleFunc("/api/v1/lifecycle", s.requireRole(auth.RoleDiagnostician, s.handleLifecycle))
	s.mux.HandleFunc("/api/v1/storage", s.requireRole(auth.RoleDiagnostician, s.handleStorage))
	s.mux.HandleFunc("/api/v1/probes", s.requireRole(auth.RoleDiagnostician, s.handleProbes))
	s.mux.HandleFunc("/api/v1/events", s.requireRole(auth.RoleViewer, s.handleEvents))
	s.mux.HandleFunc("/api/v1/events/stream", s.requireRole(auth.RoleViewer, s.handleEventStream))
	s.mux.HandleFunc("/api/v1/changes", s.requireRole(auth.RoleAdministrator, s.handleChanges))
	s.mux.HandleFunc("/api/v1/changes/", s.requireRole(auth.RoleAdministrator, s.handleChangeByID))
	s.mux.HandleFunc("/api/v1/revisions", s.requireRole(auth.RoleViewer, s.handleRevisions))
	s.mux.HandleFunc("/api/v1/backups", s.requireRole(auth.RoleAdministrator, s.handleBackups))
	s.mux.HandleFunc("/api/v1/security/audit", s.requireRole(auth.RoleDiagnostician, s.handleSecurityAudit))
	s.mux.HandleFunc("/api/v1/security", s.requireRole(auth.RoleViewer, s.handleSecurity))
	s.mux.HandleFunc("/api/v1/settings", s.requireRole(auth.RoleViewer, s.handleSettings))
	s.mux.HandleFunc("/api/v1/system", s.requireRole(auth.RoleViewer, s.handleSystem))
	s.mux.HandleFunc("/api/v1/", s.handleAPINotFound)
	s.mux.Handle("/", web.Handler())
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=()")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			var err error
			id, err = secureRandomHex(12)
			if err != nil {
				writeError(w, r, http.StatusServiceUnavailable, "entropy_unavailable", "secure random source is unavailable")
				return
			}
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(withRequestID(r.Context(), id)))
	})
}

func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := s.sessionFromRequest(r)
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "login required")
			return
		}
		if !auth.RoleAllows(session.Role, role) {
			writeError(w, r, http.StatusForbidden, "role_denied", "insufficient role")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && strings.HasPrefix(r.URL.Path, "/api/") {
			if !constantEqual(r.Header.Get("X-CSRF-Token"), session.CSRFToken) {
				writeError(w, r, http.StatusForbidden, "csrf_failed", "invalid CSRF token")
				return
			}
		}
		next(w, r.WithContext(withSession(r.Context(), session)))
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	var req LoginRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if req.Username == "" || len(req.Username) > 64 || len(req.Password) > 256 {
		writeError(w, r, http.StatusBadRequest, "invalid_login", "invalid credentials shape")
		return
	}
	session, audit, err := s.auth.Login(req.Username, req.Password, r.RemoteAddr)
	if err != nil {
		s.publishEvent(Event{Type: "auth.login_failed", Severity: "warning", ReasonCode: audit.Reason, Details: map[string]any{"user": req.Username, "remote": auth.RemoteKey(r.RemoteAddr)}})
		switch {
		case errors.Is(err, auth.ErrSetupRequired):
			writeError(w, r, http.StatusPreconditionRequired, "setup_required", "administrator is not configured")
		case errors.Is(err, auth.ErrRateLimited):
			writeError(w, r, http.StatusTooManyRequests, "rate_limited", "too many login attempts")
		default:
			// Same external error for existing and non-existing users.
			writeError(w, r, http.StatusUnauthorized, "bad_credentials", "invalid credentials")
		}
		return
	}
	http.SetCookie(w, s.sessionCookie(r, session, false))
	s.publishEvent(Event{Type: "admin.login", Severity: "info", ReasonCode: "login_success", Details: map[string]any{"user": session.User, "remote": auth.RemoteKey(r.RemoteAddr)}})
	writeData(w, r, s.auth.Public(session))
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	var req SetupRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	user, err := s.auth.SetupAdmin(req.Username, req.Password, req.SetupToken)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrWeakPassword):
			writeError(w, r, http.StatusBadRequest, "weak_password", "password is too short or too common")
		case errors.Is(err, auth.ErrSetupUnavailable):
			writeError(w, r, http.StatusConflict, "setup_unavailable", "administrator already exists")
		default:
			writeError(w, r, http.StatusUnauthorized, "setup_failed", "invalid or expired setup token")
		}
		return
	}
	s.publishEvent(Event{Type: "auth.setup_admin", Severity: "info", ReasonCode: "admin_created", Details: map[string]any{"user": user.Username}})
	writeData(w, r, map[string]any{"user": user.Username, "role": user.Role})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	session := currentSession(r)
	if session.ID == "" {
		writeError(w, r, http.StatusUnauthorized, "bad_credentials", "invalid credentials")
		return
	}
	s.auth.Logout(session.ID)
	http.SetCookie(w, s.sessionCookie(r, session, true))
	s.publishEvent(Event{Type: "auth.logout", Severity: "info", ReasonCode: "logout", Details: map[string]any{"user": session.User}})
	writeData(w, r, map[string]any{"logged_out": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, s.auth.Public(currentSession(r)))
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, s.provider.Overview(s.currentConfig()))
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, s.provider.Topology(s.currentConfig()))
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, s.provider.Devices(s.currentConfig()))
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	items := []map[string]any{}
	cfg := s.currentConfig()
	ids := make([]string, 0, len(cfg.Services))
	for id := range cfg.Services {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		svc := cfg.Services[id]
		items = append(items, map[string]any{
			"id": id, "category": svc.Category, "domains": svc.Domains,
			"allowed_paths": svc.AllowedPaths, "forbidden_paths": svc.ForbiddenPaths,
			"selected_route_tag": svc.SelectedRouteTag,
			"probe_count":        len(svc.ProbeURLs), "require_non_ru_egress": svc.RequireNonRUEgress,
			"source": "configured",
		})
	}
	if s.domainDecisions != nil {
		for _, decision := range s.domainDecisions.Snapshot() {
			category := decision.Category
			if category != "GEO_LOCKED" && (decision.TSPUStatus == "MATCH" || decision.TSPUStatus == "STALE_MATCH" || decision.SelectedType == "zapret") {
				category = "TSPU_RESTRICTED"
			}
			allowedPaths := []string{}
			forbiddenPaths := []string{}
			if _, fallback, err := serviceForClassifyRequest(serviceClassifyRequest{
				Domain: decision.Domain, Category: category,
			}); err == nil {
				allowedPaths = fallback.AllowedPaths
				forbiddenPaths = fallback.ForbiddenPaths
			}
			items = append(items, map[string]any{
				"id":                  decision.Service,
				"category":            category,
				"domains":             []string{decision.Domain},
				"allowed_paths":       allowedPaths,
				"forbidden_paths":     forbiddenPaths,
				"selected_route_tag":  decision.SelectedRoute,
				"selected_route_type": decision.SelectedType,
				"status":              decision.Status,
				"confidence":          decision.Confidence,
				"checked_at":          decision.CheckedAt,
				"expires_at":          decision.ExpiresAt,
				"source":              "automatic",
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		left, _ := items[i]["checked_at"].(time.Time)
		right, _ := items[j]["checked_at"].(time.Time)
		if !left.Equal(right) {
			return left.After(right)
		}
		return fmt.Sprint(items[i]["id"]) < fmt.Sprint(items[j]["id"])
	})
	writeData(w, r, items)
}

type serviceClassifyRequest struct {
	Domain       string   `json:"domain"`
	Category     string   `json:"category"`
	AllowedPaths []string `json:"allowed_paths,omitempty"`
	BaseVersion  int64    `json:"base_version"`
}

func serviceForClassifyRequest(request serviceClassifyRequest) (string, config.Service, error) {
	domain, err := tspu.NormalizeDomain(request.Domain)
	if err != nil {
		return "", config.Service{}, err
	}
	category := strings.ToUpper(strings.TrimSpace(request.Category))
	service := config.Service{Domains: []string{domain}}
	switch category {
	case "GEO_LOCKED":
		service.Category = category
		service.AllowedPaths = []string{"smart_dns", "vless", "drop"}
		service.ForbiddenPaths = []string{"direct", "zapret"}
		service.RequireNonRUEgress = true
	case "TSPU_RESTRICTED":
		service.Category = category
		service.AllowedPaths = []string{"zapret", "smart_dns", "vless", "direct", "drop"}
	case "DIRECT_PREFERRED":
		service.Category = category
		service.AllowedPaths = []string{"direct", "zapret", "smart_dns", "vless", "drop"}
	default:
		return "", config.Service{}, fmt.Errorf("category must be GEO_LOCKED, TSPU_RESTRICTED or DIRECT_PREFERRED")
	}
	if len(request.AllowedPaths) > 0 {
		if len(request.AllowedPaths) > 5 {
			return "", config.Service{}, fmt.Errorf("allowed_paths may contain at most five routes")
		}
		seen := map[string]bool{}
		service.AllowedPaths = make([]string, 0, len(request.AllowedPaths))
		for _, raw := range request.AllowedPaths {
			path := strings.ToLower(strings.TrimSpace(raw))
			switch path {
			case "direct", "zapret", "smart_dns", "vless", "drop":
			default:
				return "", config.Service{}, fmt.Errorf("unsupported route path %q", raw)
			}
			if seen[path] {
				return "", config.Service{}, fmt.Errorf("route path %q is duplicated", path)
			}
			if category == "GEO_LOCKED" && (path == "direct" || path == "zapret") {
				return "", config.Service{}, fmt.Errorf("GEO_LOCKED cannot use %s unless the global policy explicitly permits it", path)
			}
			seen[path] = true
			service.AllowedPaths = append(service.AllowedPaths, path)
		}
	}
	return category, service, nil
}

func (s *Server) handleServiceClassify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	var request serviceClassifyRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	category, service, err := serviceForClassifyRequest(request)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_service_rule", err.Error())
		return
	}
	domain := service.Domains[0]
	id := "user_" + strings.NewReplacer(".", "_", "-", "_").Replace(tspu.ETLDPlusOne(domain))
	change, err := s.createDraftChange(
		"Change route class for "+domain,
		"Persist the selected route class for an observed domain",
		request.BaseVersion,
		[]ChangeOp{{Type: "set", Path: "/services/" + id, Value: service}},
		currentSession(r).User,
	)
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			writeError(w, r, http.StatusConflict, "base_version_conflict", "active revision changed")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "state_store_failed", err.Error())
		return
	}
	writeData(w, r, map[string]any{"change": change, "domain": domain, "category": category})
}

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	domains := []map[string]any{}
	for id, svc := range s.currentConfig().Services {
		for _, d := range svc.Domains {
			domains = append(domains, map[string]any{"domain": d, "service": id, "source": "built-in manifest"})
		}
	}
	sort.Slice(domains, func(i, j int) bool {
		left, right := domains[i]["domain"].(string), domains[j]["domain"].(string)
		if left == right {
			return domains[i]["service"].(string) < domains[j]["service"].(string)
		}
		return left < right
	})
	writeData(w, r, domains)
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentConfig()
	writeData(w, r, map[string]any{"priority": []string{"emergency", "blocked", "device-domain", "device-service", "domain", "service", "category", "auto", "default"}, "device_policies": s.provider.Policies(cfg), "source": s.provider.Name(), "simulation": s.provider.Simulation()})
}
func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, s.currentConfig().Routes)
}
func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, traffic.ReadProcNetDev("/proc/net/dev", time.Now().UTC()))
}
func (s *Server) handleRouteHealth(w http.ResponseWriter, r *http.Request) {
	items := s.healthTracker.Snapshot()
	status := "UNVERIFIED"
	collectedAt := time.Time{}
	if len(items) == 0 {
		status = "NOT_CONFIGURED"
	}
	for _, item := range items {
		if item.UpdatedAt.After(collectedAt) {
			collectedAt = item.UpdatedAt
		}
		if item.Role == "selected" && item.State == "healthy" {
			status = "OK"
		}
	}
	writeData(w, r, map[string]any{
		"source": "bbolt+live-health-cycle", "status": status, "collected_at": collectedAt,
		"simulation": s.development, "items": items,
	})
}
func (s *Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, map[string]any{"xray": "configured", "subscription": "secret-masked", "vless_routes": countRoutes(s.currentConfig(), "vless")})
}
func (s *Server) handleSmartDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	routes := filterRoutes(s.currentConfig(), "smart_dns")
	healthByTag := map[string]probe.RouteHealth{}
	for _, item := range s.healthTracker.Snapshot() {
		if item.RouteType == "smart_dns" {
			healthByTag[item.RouteTag] = item
		}
	}
	items := make([]map[string]any, 0, len(routes))
	ready := 0
	configured := 0
	for _, route := range routes {
		health, observed := healthByTag[route.Tag]
		status := route.Status
		if observed {
			status = health.State
			if health.State == "healthy" {
				ready++
			}
		}
		resolverConfigured := route.DNSServer != "" && !strings.Contains(route.DNSServer, "PLACEHOLDER")
		if !route.Disabled && resolverConfigured {
			configured++
		}
		items = append(items, map[string]any{
			"tag": route.Tag, "status": status, "enabled": !route.Disabled,
			"resolver_configured":    resolverConfigured,
			"connect_to_resolved_ip": route.ConnectToResolvedIP,
			"health":                 health,
		})
	}
	writeData(w, r, map[string]any{
		"configured":       configured > 0,
		"configured_count": configured,
		"ready":            ready,
		"routes":           items,
		"fallback_order": map[string][]string{
			"geo":  {"smart_dns", "vless", "drop"},
			"tspu": {"zapret", "smart_dns", "vless", "direct", "drop"},
		},
		"success_contract": []string{"safe DNS answer", "connection to returned address", "content check", "egress check when required"},
	})
}

type smartDNSConfigureRequest struct {
	BaseVersion int64    `json:"base_version"`
	Endpoints   []string `json:"endpoints"`
}

func (s *Server) handleSmartDNSConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	var request smartDNSConfigureRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	active := s.currentConfig()
	routeIndexes := make([]int, 0, 2)
	for index, route := range active.Routes {
		if route.Type == "smart_dns" {
			routeIndexes = append(routeIndexes, index)
		}
	}
	if len(routeIndexes) == 0 {
		writeError(w, r, http.StatusConflict, "smart_dns_routes_missing", "configuration has no Smart DNS route slots")
		return
	}
	if request.BaseVersion <= 0 {
		writeError(w, r, http.StatusBadRequest, "invalid_base_version", "base_version must be positive")
		return
	}
	endpoints := make([]string, 0, len(request.Endpoints))
	seen := map[string]bool{}
	for _, raw := range request.Endpoints {
		endpoint, err := normalizeSmartDNSEndpoint(raw)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_smart_dns_endpoint", err.Error())
			return
		}
		if !seen[endpoint] {
			seen[endpoint] = true
			endpoints = append(endpoints, endpoint)
		}
	}
	if len(endpoints) == 0 || len(endpoints) > len(routeIndexes) {
		writeError(w, r, http.StatusBadRequest, "invalid_smart_dns_endpoint_count", fmt.Sprintf("provide 1..%d unique Smart DNS endpoints", len(routeIndexes)))
		return
	}
	operations := make([]ChangeOp, 0, len(routeIndexes)*4)
	for slot, routeIndex := range routeIndexes {
		prefix := fmt.Sprintf("/routes/%d", routeIndex)
		if slot < len(endpoints) {
			operations = append(operations,
				ChangeOp{Type: "set", Path: prefix + "/dns_server", Value: endpoints[slot]},
				ChangeOp{Type: "set", Path: prefix + "/connect_to_resolved_ip", Value: true},
				ChangeOp{Type: "set", Path: prefix + "/disabled", Value: false},
				ChangeOp{Type: "set", Path: prefix + "/status", Value: "UNVERIFIED"},
			)
			continue
		}
		operations = append(operations,
			ChangeOp{Type: "set", Path: prefix + "/disabled", Value: true},
			ChangeOp{Type: "set", Path: prefix + "/status", Value: "NOT_CONFIGURED"},
		)
	}
	session := currentSession(r)
	change, err := s.createDraftChange("Configure Smart DNS resolvers", "Validate resolvers before using VPN fallback", request.BaseVersion, operations, session.User)
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			writeError(w, r, http.StatusConflict, "base_version_conflict", "base_version does not match current revision")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "smart_dns_change_failed", err.Error())
		return
	}
	writeData(w, r, map[string]any{"change": change, "endpoint_count": len(endpoints)})
}

func normalizeSmartDNSEndpoint(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", errors.New("Smart DNS endpoint must use host:port form")
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
		return "", errors.New("Smart DNS endpoint must use a public unicast IP address")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return "", errors.New("Smart DNS endpoint port must be between 1 and 65535")
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(parsedPort, 10)), nil
}
func (s *Server) handleZapret(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, map[string]any{"status": "requires-openwrt-diagnostics", "route": filterRoutes(s.currentConfig(), "zapret")})
}
func (s *Server) handleTelegram(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, map[string]any{
		"status":                  "not_implemented",
		"telegram_notifications":  "not_implemented",
		"tg_ws_proxy":             "not_implemented",
		"route_schema_available":  true,
		"core_routing_dependency": false,
	})
}
func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, s.provider.Diagnostics(s.currentConfig()))
}
func (s *Server) handleProbes(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, 100, 500)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_limit", err.Error())
		return
	}
	items, err := s.store.ListProbeResults(limit)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "probe_history_failed", err.Error())
		return
	}
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	domain := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("domain")))
	route := strings.TrimSpace(r.URL.Query().Get("route"))
	filtered := make([]probe.RouteResult, 0, len(items))
	for _, item := range items {
		if service != "" && item.Service != service {
			continue
		}
		if domain != "" && strings.ToLower(item.Domain) != domain {
			continue
		}
		if route != "" && item.Route != route {
			continue
		}
		if s.hideSensitive {
			redactProbeResult(&item)
		}
		filtered = append(filtered, item)
	}
	status := "OK"
	if len(filtered) == 0 {
		status = "NOT_CONFIGURED"
	}
	writeData(w, r, map[string]any{"source": "bbolt", "status": status, "simulation": s.development, "items": filtered})
}
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, 100, 500)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_limit", err.Error())
		return
	}
	rows, err := s.store.ListRaw("events")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "event_history_failed", err.Error())
		return
	}
	byID := make(map[string]Event, len(rows)+limit)
	for _, raw := range rows {
		var event Event
		if err := json.Unmarshal(raw, &event); err != nil {
			writeError(w, r, http.StatusInternalServerError, "event_history_corrupt", "persisted event cannot be decoded")
			return
		}
		byID[eventIdentity(event)] = event
	}
	for _, event := range s.broker.Recent(0, limit) {
		byID[eventIdentity(event)] = event
	}
	items := make([]Event, 0, len(byID))
	for _, event := range byID {
		if s.hideSensitive {
			event.Details = sanitizeEventDetails(event.Details)
		}
		items = append(items, event)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Time == items[j].Time {
			if items[i].StreamEpoch == items[j].StreamEpoch {
				return items[i].ID < items[j].ID
			}
			return items[i].StreamEpoch < items[j].StreamEpoch
		}
		return items[i].Time < items[j].Time
	})
	if len(items) > limit {
		items = items[len(items)-limit:]
	}
	writeData(w, r, items)
}
func (s *Server) handleRevisions(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, 100, 500)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_limit", err.Error())
		return
	}
	rows, err := s.store.ListRaw("revisions")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "revision_history_failed", err.Error())
		return
	}
	items := make([]revisionRecord, 0, len(rows))
	for _, raw := range rows {
		var item revisionRecord
		if err := json.Unmarshal(raw, &item); err != nil {
			writeError(w, r, http.StatusInternalServerError, "revision_history_corrupt", "persisted revision cannot be decoded")
			return
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		left, right := items[i].CreatedAt, items[j].CreatedAt
		if items[i].CommittedAt != nil {
			left = *items[i].CommittedAt
		}
		if items[j].CommittedAt != nil {
			right = *items[j].CommittedAt
		}
		return left.After(right)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	activeRevision, configVersion := s.activeIdentity()
	writeData(w, r, map[string]any{"source": "bbolt", "status": statusForCount(len(items)), "active_revision": activeRevision, "config_version": configVersion, "items": items})
}
func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, 50, 100)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_limit", err.Error())
		return
	}
	items, err := s.store.ListBackups(limit)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "backup_history_failed", err.Error())
		return
	}
	status := statusForCount(len(items))
	for _, item := range items {
		if item.Status != "OK" {
			status = "DEGRADED"
			break
		}
	}
	writeData(w, r, map[string]any{"source": "bbolt+verified-files", "status": status, "items": items})
}
func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, map[string]any{"listen_default": "127.0.0.1", "hide_sensitive": s.hideSensitive, "secrets": "masked", "auth": "configured-required", "simulation": s.provider.Simulation()})
}
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentConfig()
	activeRevision, configVersion := s.activeIdentity()
	writeData(w, r, map[string]any{
		"source": "active-config+bbolt", "status": "OK", "active_revision": activeRevision,
		"config_version": configVersion, "config_schema_version": cfg.Version,
		"platform": cfg.Platform, "policy": cfg.Policy,
		"storage": map[string]any{
			"event_retention_days": cfg.Storage.EventRetentionDays, "changeset_retention_days": cfg.Storage.ChangeSetRetentionDays,
			"transaction_retention_days": cfg.Storage.TransactionRetentionDays, "max_probe_results": cfg.Storage.MaxProbeResults,
			"backup_interval_hours": cfg.Storage.BackupIntervalHours, "compact_interval_days": cfg.Storage.CompactIntervalDays,
			"max_state_backups": cfg.Storage.MaxStateBackups, "max_database_bytes": cfg.Storage.MaxDatabaseBytes,
			"max_auto_domains": cfg.Storage.MaxAutoDomains,
		},
		"xray": map[string]any{
			"configured": countRoutes(cfg, "vless") > 0, "probe_socks_base_port": cfg.Xray.ProbeSocksBasePort,
			"dns_proxy_base_port": cfg.Xray.DNSProxyBasePort, "transparent_port": cfg.Xray.TransparentPort,
			"outbound_bundle_sha256": cfg.Xray.OutboundBundleSHA256,
		},
		"notifications": map[string]any{
			"telegram_secret_path_configured": strings.TrimSpace(cfg.Notifications.TelegramSecretFile) != "",
			"webhook_secret_path_configured":  strings.TrimSpace(cfg.Notifications.HTTPSWebhookSecretFile) != "",
			"delivery_runtime":                "not_implemented",
			"dedupe_seconds":                  cfg.Notifications.DedupeSeconds,
		},
		"privacy": map[string]any{"hide_ips": s.hideSensitive, "domain_logging": "normal"},
	})
}
func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, s.provider.System(s.currentConfig()))
}

func (s *Server) handleSecurityAudit(w http.ResponseWriter, r *http.Request) {
	report := security.Audit(s.currentConfig())
	writeData(w, r, report)
}

func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		out := make([]ChangeSet, 0, len(s.changes))
		for _, c := range s.changes {
			out = append(out, c)
		}
		s.mu.Unlock()
		sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
		writeData(w, r, out)
	case http.MethodPost:
		var req ChangeSetRequest
		if err := readJSON(r, &req); err != nil {
			writeError(w, r, 400, "bad_json", err.Error())
			return
		}
		if strings.TrimSpace(req.Title) == "" || len(req.Title) > 120 {
			writeError(w, r, 400, "invalid_title", "title is required and must be <=120 chars")
			return
		}
		if len(req.Operations) == 0 {
			writeError(w, r, 400, "operations_required", "at least one explicit operation is required")
			return
		}
		session := currentSession(r)
		cs, err := s.createDraftChange(req.Title, req.Description, req.BaseVersion, req.Operations, session.User)
		if errors.Is(err, errBaseVersionConflict) {
			writeError(w, r, http.StatusConflict, "base_version_conflict", "base_version does not match current revision")
			return
		}
		if err != nil {
			writeError(w, r, 500, "state_store_failed", err.Error())
			return
		}
		writeData(w, r, cs)
	default:
		writeError(w, r, 405, "method_not_allowed", "GET or POST required")
	}
}

func (s *Server) handleChangeByID(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/changes/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, r, 404, "not_found", "change not found")
		return
	}
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	s.mu.Lock()
	cs, ok := s.changes[id]
	s.mu.Unlock()
	if !ok {
		writeError(w, r, 404, "not_found", "change not found")
		return
	}
	if r.Method == http.MethodGet && action == "" {
		writeData(w, r, cs)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, r, 405, "method_not_allowed", "POST required")
		return
	}
	var req ChangeActionRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	release := s.acquireChangeActionLock(id)
	defer release()
	s.mu.Lock()
	cs, ok = s.changes[id]
	s.mu.Unlock()
	if !ok {
		writeError(w, r, http.StatusNotFound, "not_found", "change not found")
		return
	}
	if req.Version != 0 && req.Version != cs.Version {
		writeError(w, r, http.StatusConflict, "change_version_conflict", "change version is stale")
		return
	}
	var failure *actionFailure
	switch action {
	case "validate":
		cs, failure = s.validateChangeSet(cs)
	case "apply":
		if s.requireManagementProof && !cs.Noop {
			cs, failure = s.prepareManagementProof(r, req, cs)
		}
		if failure == nil {
			cs, failure = s.applyChangeSet(r.Context(), cs)
		}
	case "confirm":
		if s.requireManagementProof && !cs.Noop {
			failure = s.verifyManagementConfirmation(r, req, cs)
		}
		if failure == nil {
			cs, failure = s.confirmChangeSet(r.Context(), cs)
		}
	case "rollback":
		cs, failure = s.rollbackChangeSet(r.Context(), cs, false)
	case "delete":
		if cs.State != "draft" && cs.State != "rolled_back" && cs.State != "expired" && cs.State != "failed" && cs.State != "requires_device" {
			writeError(w, r, http.StatusConflict, "invalid_transition", "only inactive changes can be deleted")
			return
		}
		s.mu.Lock()
		delete(s.changes, id)
		s.mu.Unlock()
		if err := s.store.Delete("changes", id); err != nil {
			writeError(w, r, 500, "state_store_failed", err.Error())
			return
		}
		writeData(w, r, map[string]any{"deleted": true})
		return
	default:
		writeError(w, r, 404, "bad_action", "unknown change action")
		return
	}
	if failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	writeData(w, r, cs)
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, r, 500, "sse_unsupported", "streaming unsupported")
		return
	}
	afterID := int64(0)
	streamEpoch := s.broker.Epoch()
	if last := strings.TrimSpace(r.Header.Get("Last-Event-ID")); last != "" {
		parsed, err := strconv.ParseInt(last, 10, 64)
		if err != nil || parsed < 0 {
			writeError(w, r, http.StatusBadRequest, "bad_last_event_id", "Last-Event-ID must be a non-negative integer")
			return
		}
		afterID = parsed
		if previousEpoch := strings.TrimSpace(r.Header.Get("Last-Event-Epoch")); previousEpoch != "" && previousEpoch != streamEpoch {
			afterID = 0
		}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Event-Stream-Epoch", streamEpoch)
	ch, ok := s.broker.Subscribe()
	if !ok {
		writeError(w, r, http.StatusTooManyRequests, "too_many_event_streams", "too many open event streams")
		return
	}
	defer s.broker.Unsubscribe(ch)
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for _, ev := range s.broker.Recent(afterID, 20) {
		writeSSE(w, ev)
	}
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, ev)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	recovery := s.currentRecoveryStatus()
	status := "ok"
	if recovery.Status == "error" {
		status = "degraded"
	}
	writeData(w, r, map[string]any{
		"status": status, "provider": s.provider.Name(), "simulation": s.provider.Simulation(),
		"recovery_status": recovery.Status, "recovery_reason_code": recovery.ReasonCode,
		"recovery_reason": recovery.Reason, "active_revision": recovery.RevisionID,
		"time": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleAPINotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotFound, "not_found", "unknown API endpoint")
}

func (s *Server) sessionFromRequest(r *http.Request) (auth.Session, bool) {
	cookie, err := r.Cookie("rp_session")
	if err != nil {
		return auth.Session{}, false
	}
	return s.auth.Session(cookie.Value)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		ct := r.Header.Get("Content-Type")
		if ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
			return fmt.Errorf("content-type must be application/json")
		}
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing JSON is not allowed")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON is not allowed")
	}
	return nil
}

func writeData(w http.ResponseWriter, r *http.Request, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(Envelope{RequestID: requestID(r), Data: data})
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{RequestID: requestID(r), Error: APIError{Code: code, Message: message}})
}

func writeSSE(w http.ResponseWriter, ev Event) {
	b, _ := json.Marshal(ev)
	fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", ev.ID, ev.Type, b)
}

func (s *Server) sessionCookie(r *http.Request, session auth.Session, clear bool) *http.Cookie {
	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	value := session.ID
	expires := session.ExpiresAt
	if clear {
		maxAge = -1
		value = ""
		expires = time.Unix(0, 0)
	}
	return &http.Cookie{
		Name:     "rp_session",
		Value:    value,
		Path:     "/api/v1",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
		Expires:  expires,
	}
}

func constantEqual(a, b string) bool {
	if len(a) != len(b) {
		subtleA := []byte(a)
		subtleB := []byte(b)
		if len(subtleA) < len(subtleB) {
			subtleA = append(subtleA, make([]byte, len(subtleB)-len(subtleA))...)
		}
		if len(subtleB) < len(subtleA) {
			subtleB = append(subtleB, make([]byte, len(subtleA)-len(subtleB))...)
		}
		_ = subtle.ConstantTimeCompare(subtleA, subtleB)
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func loadPersistedChangeSets(store *state.Store) (map[string]ChangeSet, error) {
	out := map[string]ChangeSet{}
	rows, err := store.ListRaw("changes")
	if err != nil {
		return nil, err
	}
	for _, raw := range rows {
		var cs ChangeSet
		if err := json.Unmarshal(raw, &cs); err != nil {
			return nil, err
		}
		if cs.ID != "" {
			out[cs.ID] = cs
		}
	}
	return out, nil
}

func (s *Server) persistChangeSet(cs ChangeSet) error {
	return s.store.SaveJSON("changes", cs.ID, cs)
}

func applyConfigOperation(candidate map[string]any, op ChangeOp) (bool, error) {
	parts, err := splitJSONPointer(op.Path)
	if err != nil {
		return false, err
	}
	if len(parts) == 0 {
		return false, fmt.Errorf("empty path")
	}
	if _, ok := candidate[parts[0]]; !ok {
		return false, fmt.Errorf("path is outside typed config model")
	}
	parent, err := pointerParent(candidate, parts[:len(parts)-1])
	if err != nil {
		return false, err
	}
	key := parts[len(parts)-1]
	switch p := parent.(type) {
	case map[string]any:
		if op.Type == "delete" {
			if _, ok := p[key]; !ok {
				return false, fmt.Errorf("delete target does not exist")
			}
			delete(p, key)
			return true, nil
		}
		if op.Type == "update" {
			if _, ok := p[key]; !ok {
				return false, fmt.Errorf("update target does not exist")
			}
		}
		if op.Type == "add" {
			if _, ok := p[key]; ok {
				return false, fmt.Errorf("add target already exists")
			}
		}
		p[key] = op.Value
		return true, nil
	case []any:
		if op.Type == "add" || op.Type == "delete" {
			return false, fmt.Errorf("array add/delete is not supported")
		}
		idx, err := strconv.Atoi(key)
		if err != nil {
			return false, fmt.Errorf("array index required")
		}
		if idx < 0 || idx >= len(p) {
			return false, fmt.Errorf("array index out of range")
		}
		p[idx] = op.Value
		return true, nil
	default:
		return false, fmt.Errorf("parent is not editable")
	}
}

func splitJSONPointer(path string) ([]string, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("path must start with /")
	}
	raw := strings.Split(strings.TrimPrefix(path, "/"), "/")
	parts := make([]string, 0, len(raw))
	for _, part := range raw {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		unescaped, err := url.PathUnescape(part)
		if err != nil {
			return nil, err
		}
		parts = append(parts, unescaped)
	}
	return parts, nil
}

func pointerParent(root any, parts []string) (any, error) {
	cur := root
	for _, part := range parts {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[part]
			if !ok {
				return nil, fmt.Errorf("path segment does not exist: %s", part)
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("array index required")
			}
			if idx < 0 || idx >= len(node) {
				return nil, fmt.Errorf("array index out of range")
			}
			cur = node[idx]
		default:
			return nil, fmt.Errorf("path segment is not a container: %s", part)
		}
	}
	return cur, nil
}

func countRoutes(cfg *config.Config, typ string) int             { return len(filterRoutes(cfg, typ)) }
func filterRoutes(cfg *config.Config, typ string) []config.Route { return cfg.RoutesByType(typ) }

func (s *Server) activeIdentity() (string, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeRevision, s.configVersion
}

func queryLimit(r *http.Request, fallback, maximum int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 || value > maximum {
		return 0, fmt.Errorf("limit must be between 1 and %d", maximum)
	}
	return value, nil
}

func statusForCount(count int) string {
	if count == 0 {
		return "NOT_CONFIGURED"
	}
	return "OK"
}

func eventIdentity(event Event) string {
	return fmt.Sprintf("%s:%020d", event.StreamEpoch, event.ID)
}

func redactProbeResult(result *probe.RouteResult) {
	result.DNSResolver = ""
	result.ResolvedIP = ""
	result.ConnectedIP = ""
	result.LocalIP = ""
	for i := range result.Checks {
		result.Checks[i].DNSResolver = ""
		result.Checks[i].ResolvedIPs = nil
		result.Checks[i].ConnectedIP = ""
		result.Checks[i].LocalIP = ""
	}
}

func sanitizeEventDetails(details map[string]any) map[string]any {
	if details == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(details))
	for key, value := range details {
		if sensitiveEventKey(key) {
			out[key] = "[redacted]"
			continue
		}
		out[key] = sanitizeEventValue(value)
	}
	return out
}

func sanitizeEventValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return sanitizeEventDetails(typed)
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			out[i] = sanitizeEventValue(typed[i])
		}
		return out
	default:
		return value
	}
}

func sensitiveEventKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "remote" || key == "ip" || key == "address" || strings.HasSuffix(key, "_ip") || strings.HasSuffix(key, "_address") {
		return true
	}
	for _, fragment := range []string{"password", "token", "secret", "private_key", "subscription_url", "uuid", "cookie"} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}
