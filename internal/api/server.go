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
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"router-policy/internal/adapter"
	"router-policy/internal/auth"
	"router-policy/internal/component"
	"router-policy/internal/config"
	"router-policy/internal/discovery"
	"router-policy/internal/domaincache"
	"router-policy/internal/externalsocks"
	"router-policy/internal/health"
	"router-policy/internal/managementproof"
	"router-policy/internal/netpolicy"
	"router-policy/internal/planner"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
	"router-policy/internal/secureid"
	"router-policy/internal/security"
	"router-policy/internal/state"
	"router-policy/internal/telegramnotify"
	"router-policy/internal/traffic"
	"router-policy/internal/tspu"
	"router-policy/internal/vpnsub"
	"router-policy/internal/web"
	"router-policy/internal/zapret"
)

var secureRandomHex = secureid.Hex

type Options struct {
	Auth                    *auth.Store
	Provider                platform.Provider
	State                   *state.Store
	ProductionAdapter       adapter.Interface
	SubscriptionPreparer    SubscriptionPreparer
	ZapretSetupChecker      zapret.SetupChecker
	ExternalSOCKSChecker    externalsocks.Checker
	TelegramNotifier        *telegramnotify.Manager
	ComponentManager        ComponentManager
	ZapretCalibration       *zapret.CalibrationManager
	VLESSThroughputTester   vpnsub.ThroughputTester
	HWIDFingerprintProvider vpnsub.FingerprintProvider
	ProbeEngineFactory      func(*config.Config) health.ProbeEngine
	TSPURefresh             TSPURefreshFunc
	DNSObservationPath      string
	Development             bool
	DeferRecovery           bool
	ManagementProofs        *managementproof.Manager
	RequireManagementProof  bool
	SmartDNSValidator       SmartDNSValidator
	DiscoveryNow            func() time.Time
	DomainChecker           DomainChecker
	// RouteAssignmentRuntime is intentionally optional.  Until a production
	// consumer can atomically materialize a revision-bound domain mapping in
	// the owned nft/dnsmasq dataplane, discovery must remain suggestion-only.
	RouteAssignmentRuntime RouteAssignmentRuntime
}

type SubscriptionPreparer interface {
	Prepare(context.Context, *config.Config) (vpnsub.PreparedBundle, error)
}

type ProbeBudgetAware interface {
	SetProbeBudget(chan struct{})
}

type ComponentManager interface {
	List(context.Context) ([]component.Status, error)
	Status(context.Context, component.Kind, bool) (component.Status, error)
	Execute(context.Context, component.Request) (component.Result, error)
}

type TGWSComponentManager interface {
	TGWSStatus(context.Context) (component.TGWSStatus, error)
	ConfigureTGWS(context.Context, component.TGWSConfigRequest) (component.TGWSConfigureResult, error)
}

type TSPURefreshFunc func(context.Context, *config.Config, time.Time) (tspu.Cache, error)

type tspuDelayFunc func(time.Duration, int, bool) time.Duration

type actionLockEntry struct {
	mu   sync.Mutex
	refs int
}

type Server struct {
	cfg                     *config.Config
	auth                    *auth.Store
	provider                platform.Provider
	store                   *state.Store
	adapter                 adapter.Interface
	subscriptionPreparer    SubscriptionPreparer
	zapretSetupChecker      zapret.SetupChecker
	externalSOCKSChecker    externalsocks.Checker
	telegramNotifier        *telegramnotify.Manager
	componentManager        ComponentManager
	routeAssignmentRuntime  RouteAssignmentRuntime
	zapretCalibration       *zapret.CalibrationManager
	vlessThroughputTester   vpnsub.ThroughputTester
	hwidFingerprintProvider vpnsub.FingerprintProvider
	probeEngineFactory      func(*config.Config) health.ProbeEngine
	tspuRefresh             TSPURefreshFunc
	tspuDelay               tspuDelayFunc
	healthTracker           *probe.HealthTracker
	domainDecisions         *domaincache.Manager
	dnsObservationPath      string
	development             bool
	broker                  *EventBroker
	mux                     *http.ServeMux
	mu                      sync.Mutex
	// mutationGate closes the recovery-to-mutation TOCTOU window. Recovery
	// status transitions take the write side; every write-capable operation
	// holds the read side for its entire lifetime.
	mutationGate           sync.RWMutex
	changes                map[string]ChangeSet
	actionLocks            map[string]*actionLockEntry
	autoApplyMu            sync.Mutex
	autoApplyInFlight      map[string]bool
	autoApplyCtx           context.Context
	autoApplyCancel        context.CancelFunc
	autoApplyWG            sync.WaitGroup
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
	smartDNSValidator      SmartDNSValidator
	discoveryNow           func() time.Time
	domainChecker          DomainChecker
	discoverySuggestionMap map[string]discoverySuggestion
	discoveryObservations  []discoveryObservation
	discoveryCursor        int64
	discoveryLagBytes      int64
	discoveryEmitted       uint64
	discoveryLastProgress  time.Time
	discoveryLastEmission  time.Time
	discoveryDropped       uint64
	discoveryApplied       uint64
	discoveryFailed        uint64
	discoveryRecent        map[string]time.Time
	discoveryInFlight      map[string]bool
	discoveryPending       map[string]bool
	discoveryQueue         chan discovery.Observation
	probeBudget            chan struct{}
	routeFailureQueue      chan routeFailureReport
	routeFailureMu         sync.Mutex
	routeFailureRecent     map[string]time.Time
	routeFailureCooldown   map[string]time.Time
	routeRecoveryNext      map[string]time.Time
	routeRecoveryBackoff   map[string]time.Duration
	revalidationMu         sync.Mutex
	revalidationNext       map[string]time.Time
	deferRecovery          bool
	hotplugEventDigest     string
	schedulerOnce          sync.Once
	schedulerCancel        context.CancelFunc
	schedulerWG            sync.WaitGroup
	closeOnce              sync.Once
	closeErr               error
}

// tryLockSubscription prevents a slow provider or speed measurement from
// turning a second scheduler/HTTP request into a blocked handler.  The
// operation lock still serializes the actual work; callers must report the
// busy condition and let the next bounded scheduling interval retry.
func (s *Server) tryLockSubscription() bool {
	return s.subscriptionMu.TryLock()
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
	smartDNSValidator := opts.SmartDNSValidator
	if smartDNSValidator == nil {
		smartDNSValidator = probe.ValidateSmartDNSCandidate
	}
	discoveryNow := opts.DiscoveryNow
	if discoveryNow == nil {
		discoveryNow = func() time.Time { return time.Now().UTC() }
	}
	domainChecker := opts.DomainChecker
	if domainChecker == nil {
		domainChecker = planner.CheckDomain
	}
	externalSOCKSChecker := opts.ExternalSOCKSChecker
	if externalSOCKSChecker == nil {
		externalSOCKSChecker = externalsocks.LocalChecker{}
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
	hwidFingerprintProvider := opts.HWIDFingerprintProvider
	if hwidFingerprintProvider == nil {
		hwidFingerprintProvider = vpnsub.SystemFingerprintProvider{}
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
		dnsObservationPath = config.DNSObservationPath(activeConfig.Storage.RuntimeDir)
	}
	probeBudgetSize := activeConfig.Policy.ProbeBudget
	if probeBudgetSize <= 0 || probeBudgetSize > 4 {
		probeBudgetSize = 4
	}
	discoveryQueueLimit := activeConfig.Policy.DiscoveryQueueLimit
	if discoveryQueueLimit <= 0 || discoveryQueueLimit > 32 {
		discoveryQueueLimit = 32
	}
	broker, err := NewEventBroker(512)
	if err != nil {
		_ = stateStore.Close()
		return nil, err
	}
	telegramNotifier := opts.TelegramNotifier
	if telegramNotifier == nil {
		secretFile := strings.TrimSpace(activeConfig.Notifications.TelegramSecretFile)
		if secretFile == "" {
			secretFile = filepath.Join(activeConfig.Storage.StateDir, "secrets", "telegram.json")
		}
		telegramNotifier, err = telegramnotify.New(telegramnotify.Options{
			SecretFile: secretFile,
			DedupeFor:  time.Duration(activeConfig.Notifications.DedupeSeconds) * time.Second,
		})
		if err != nil {
			_ = stateStore.Close()
			return nil, fmt.Errorf("initialize Telegram notifications: %w", err)
		}
	}
	autoApplyCtx, autoApplyCancel := context.WithCancel(context.Background())
	s := &Server{
		cfg:                     cfg,
		auth:                    authStore,
		provider:                provider,
		store:                   stateStore,
		adapter:                 opts.ProductionAdapter,
		subscriptionPreparer:    opts.SubscriptionPreparer,
		zapretSetupChecker:      opts.ZapretSetupChecker,
		externalSOCKSChecker:    externalSOCKSChecker,
		telegramNotifier:        telegramNotifier,
		componentManager:        opts.ComponentManager,
		routeAssignmentRuntime:  opts.RouteAssignmentRuntime,
		zapretCalibration:       opts.ZapretCalibration,
		vlessThroughputTester:   opts.VLESSThroughputTester,
		hwidFingerprintProvider: hwidFingerprintProvider,
		probeEngineFactory:      probeEngineFactory,
		tspuRefresh:             tspuRefresh,
		tspuDelay:               randomTSPUDelay,
		healthTracker:           probe.NewHealthTracker(persistedHealth),
		domainDecisions:         domainDecisions,
		dnsObservationPath:      dnsObservationPath,
		development:             opts.Development,
		broker:                  broker,
		mux:                     http.NewServeMux(),
		changes:                 changes,
		actionLocks:             map[string]*actionLockEntry{},
		autoApplyInFlight:       map[string]bool{},
		autoApplyCtx:            autoApplyCtx,
		autoApplyCancel:         autoApplyCancel,
		timers:                  map[string]*time.Timer{},
		activeConfig:            activeConfig,
		activeRevision:          activeRevision,
		configVersion:           configVersion,
		hideSensitive:           true,
		managementProofs:        managementProofs,
		requireManagementProof:  requireManagementProof,
		smartDNSValidator:       smartDNSValidator,
		discoveryNow:            discoveryNow,
		domainChecker:           domainChecker,
		discoverySuggestionMap:  map[string]discoverySuggestion{},
		discoveryObservations:   make([]discoveryObservation, 0, maxDiscoveryObservations),
		discoveryRecent:         map[string]time.Time{},
		discoveryInFlight:       map[string]bool{},
		discoveryPending:        map[string]bool{},
		discoveryQueue:          make(chan discovery.Observation, discoveryQueueLimit),
		probeBudget:             make(chan struct{}, probeBudgetSize),
		routeFailureQueue:       make(chan routeFailureReport, 16),
		routeFailureRecent:      map[string]time.Time{},
		routeFailureCooldown:    map[string]time.Time{},
		routeRecoveryNext:       map[string]time.Time{},
		routeRecoveryBackoff:    map[string]time.Duration{},
		revalidationNext:        map[string]time.Time{},
		deferRecovery:           opts.DeferRecovery,
	}
	s.loadPersistedDiscoverySuggestions()
	if preparer, ok := s.subscriptionPreparer.(ProbeBudgetAware); ok {
		preparer.SetProbeBudget(s.probeBudget)
	}
	s.adaptiveZapret, err = buildAdaptiveRuntime(activeConfig, stateStore)
	if err != nil {
		telegramNotifier.Close()
		_ = stateStore.Close()
		return nil, fmt.Errorf("initialize adaptive Zapret: %w", err)
	}
	s.routes()
	if err := s.recoverTransactions(context.Background()); err != nil {
		telegramNotifier.Close()
		_ = stateStore.Close()
		return nil, err
	}
	s.adaptiveZapret, err = buildAdaptiveRuntime(s.currentConfig(), stateStore)
	if err != nil {
		telegramNotifier.Close()
		_ = stateStore.Close()
		return nil, fmt.Errorf("refresh adaptive Zapret after recovery: %w", err)
	}
	if opts.DeferRecovery {
		now := time.Now().UTC()
		if err := s.setRecoveryStatus(recoveryStatus{Status: "starting", RevisionID: activeRevision, StartedAt: now}); err != nil {
			// setRecoveryStatus installs a memory fence when persistence fails;
			// construction can continue so health/rescue diagnostics remain
			// available, but no mutation will be admitted.
			_ = err
		}
	} else {
		s.recoverCommittedDataplane(context.Background())
		if recoveryStatusAllowsMutation(s.currentRecoveryStatus()) {
			if err := s.reconcileRouteAssignments(context.Background()); err != nil {
				revision, _ := s.activeIdentity()
				s.setRecoveryStatus(failedRecovery(time.Now().UTC(), "route_assignment_reconcile_failed", err.Error(), adapter.RecoveryTarget{RevisionID: revision}))
			}
		}
	}
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
		s.autoApplyMu.Lock()
		if s.autoApplyCancel != nil {
			s.autoApplyCancel()
		}
		s.autoApplyMu.Unlock()
		s.autoApplyWG.Wait()
		if s.telegramNotifier != nil {
			s.telegramNotifier.Close()
		}
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

		if s.deferRecovery {
			s.schedulerWG.Add(1)
			go func() {
				defer s.schedulerWG.Done()
				recoveryCtx, cancelRecovery := context.WithTimeout(schedulerCtx, 90*time.Second)
				defer cancelRecovery()
				s.recoverCommittedDataplane(recoveryCtx)
				if schedulerCtx.Err() == nil && recoveryStatusAllowsMutation(s.currentRecoveryStatus()) {
					if err := s.reconcileRouteAssignments(recoveryCtx); err != nil {
						revision, _ := s.activeIdentity()
						s.setRecoveryStatus(failedRecovery(time.Now().UTC(), "route_assignment_reconcile_failed", err.Error(), adapter.RecoveryTarget{RevisionID: revision}))
						return
					}
					s.startOperationalSchedulers(schedulerCtx)
				}
			}()
			return
		}
		s.startOperationalSchedulers(schedulerCtx)
	})
}

func (s *Server) reconcileRouteAssignments(ctx context.Context) error {
	reconciler, ok := s.routeAssignmentRuntime.(RouteAssignmentReconciler)
	if !ok {
		return nil
	}
	s.mu.Lock()
	revision := s.activeRevision
	s.mu.Unlock()
	if revision == "" {
		return nil
	}
	// The runtime independently reads the durable binding and refuses stale
	// manifests; passing only the context keeps controller code from gaining
	// any path or shell authority.
	return reconciler.ReconcileRouteAssignments(ctx)
}

func (s *Server) startOperationalSchedulers(schedulerCtx context.Context) {
	// Resume only explicitly marked product operations after recovery has
	// admitted mutations. Unmarked historical drafts remain user-controlled.
	s.resumeAutoApplyChanges()
	interval := time.Duration(s.cfg.Policy.InventoryHealthIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	if interval < time.Hour {
		interval = time.Hour
	}
	s.schedulerWG.Add(1)
	go func() {
		defer s.schedulerWG.Done()
		if !waitForScheduler(schedulerCtx, startupHealthDelay()) {
			return
		}
		s.runHealthCycle(schedulerCtx)
		maintenance := time.NewTicker(6 * time.Hour)
		defer maintenance.Stop()
		for {
			next := time.NewTimer(jitteredHealthInterval(interval))
			select {
			case <-schedulerCtx.Done():
				next.Stop()
				return
			case <-next.C:
				s.runHealthCycle(schedulerCtx)
			case <-maintenance.C:
				if err := s.store.Maintain(time.Now().UTC()); err != nil {
					s.publishEvent(Event{Type: "storage.maintenance_failed", Severity: "error", ReasonCode: "bbolt_maintenance_failed", Details: map[string]any{"error": err.Error()}})
				}
				if err := s.prunePersistedDiscoverySuggestions(time.Now().UTC()); err != nil {
					s.publishEvent(Event{Type: "discovery.storage", Severity: "warning", ReasonCode: "suggestion_retention_cleanup_failed", Details: map[string]any{"error": err.Error()}})
				}
			}
			next.Stop()
		}
	}()
	s.startTSPUScheduler(schedulerCtx)
	s.startSubscriptionScheduler(schedulerCtx)
	s.startHotplugObserver(schedulerCtx)
	s.startDNSDiscovery(schedulerCtx)
	s.startRouteFailureScheduler(schedulerCtx)
	s.startFailedRouteRecoveryScheduler(schedulerCtx)
	s.startClassifiedRevalidationScheduler(schedulerCtx)
}

func (s *Server) startTSPUScheduler(ctx context.Context) {
	s.schedulerWG.Add(1)
	go func() {
		defer s.schedulerWG.Done()
		s.runTSPUScheduler(ctx)
	}()
}

func (s *Server) startSubscriptionScheduler(ctx context.Context) {
	if s.subscriptionPreparer == nil {
		return
	}
	s.schedulerWG.Add(1)
	go func() {
		defer s.schedulerWG.Done()
		failures := 0
		for {
			delay := s.subscriptionRefreshDelay(time.Now().UTC())
			if backoff := subscriptionRefreshBackoff(failures); backoff > delay {
				delay = backoff
			}
			if !waitForScheduler(ctx, delay) {
				return
			}
			if failure := s.mutationFailureNow(); failure != nil {
				s.publishEvent(Event{Type: "subscription.refresh", Severity: "warning", ReasonCode: "mutation_fenced", Details: map[string]any{"code": failure.Code}})
				continue
			}
			if !s.tryLockSubscription() {
				s.publishEvent(Event{Type: "subscription.refresh", Severity: "info", ReasonCode: "subscription_refresh_busy"})
				continue
			}
			active := s.currentConfig()
			refreshCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			_, err := s.subscriptionPreparer.Prepare(refreshCtx, active)
			cancel()
			s.subscriptionMu.Unlock()
			if err != nil {
				failures++
				s.publishEvent(Event{Type: "subscription.refresh", Severity: "warning", ReasonCode: "subscription_refresh_failed", Details: map[string]any{"error": err.Error()}})
			} else {
				failures = 0
				s.publishEvent(Event{Type: "subscription.refresh", Severity: "info", ReasonCode: "subscription_refresh_completed"})
			}
		}
	}()
}

// subscriptionRefreshBackoff prevents a provider that keeps returning an
// expired/invalid subscription from being fetched every minute forever. The
// delay is bounded, jittered, and independent from the provider expiry
// calculation; a successful refresh resets it.
func subscriptionRefreshBackoff(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	base := time.Minute
	for attempt := 1; attempt < failures && base < 6*time.Hour; attempt++ {
		base *= 2
	}
	if base > 6*time.Hour {
		base = 6 * time.Hour
	}
	var sample [2]byte
	if _, err := rand.Read(sample[:]); err != nil {
		return base
	}
	delay := jitterTSPUDelay(base, uint16(sample[0])<<8|uint16(sample[1]))
	if delay < time.Minute {
		return time.Minute
	}
	if delay > 6*time.Hour {
		return 6 * time.Hour
	}
	return delay
}

func (s *Server) subscriptionRefreshDelay(now time.Time) time.Duration {
	active := s.currentConfig()
	if active == nil {
		return 24 * time.Hour
	}
	pool, err := vpnsub.LoadPool(vpnsub.PoolPath(active.Storage.StateDir))
	if err != nil {
		return jitteredHealthInterval(24 * time.Hour)
	}
	var earliest time.Time
	for _, source := range pool.Sources {
		if source.ExpiresAt == "" {
			continue
		}
		expires, parseErr := time.Parse(time.RFC3339, source.ExpiresAt)
		if parseErr == nil && (earliest.IsZero() || expires.Before(earliest)) {
			earliest = expires
		}
	}
	if earliest.IsZero() {
		return jitteredHealthInterval(24 * time.Hour)
	}
	delay := earliest.Sub(now) - 1*time.Hour
	if delay < time.Minute {
		return time.Minute
	}
	return delay
}

func (s *Server) startDNSDiscovery(ctx context.Context) {
	if !s.currentConfig().Policy.UnknownDomainBackgroundCheck || s.dnsObservationPath == "" {
		return
	}
	s.schedulerWG.Add(1)
	go func() {
		defer s.schedulerWG.Done()
		workers := 1
		for i := 0; i < workers; i++ {
			s.schedulerWG.Add(1)
			go func() {
				defer s.schedulerWG.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case observation, ok := <-s.discoveryQueue:
						if !ok {
							return
						}
						s.discoverDomain(ctx, observation)
						s.releasePendingDiscovery(observation.Domain)
					}
				}
			}()
		}
		var dropped uint64
		var lastDropNotice time.Time
		watcher := discovery.Watcher{
			Path:       s.dnsObservationPath,
			StartAtEnd: true,
			Progress: func(cursor int64, emitted uint64) {
				info, _ := os.Stat(s.dnsObservationPath)
				now := s.discoveryNow()
				s.mu.Lock()
				s.discoveryCursor = cursor
				s.discoveryEmitted += emitted
				s.discoveryLastProgress = now
				if emitted > 0 {
					s.discoveryLastEmission = now
				}
				if info != nil && info.Size() >= cursor {
					s.discoveryLagBytes = info.Size() - cursor
				}
				s.mu.Unlock()
			},
			Emit: func(observationContext context.Context, observation discovery.Observation) {
				s.recordDiscoveryObservation(observation)
				_, queueFull := s.enqueueDiscoveryObservation(observation)
				if queueFull {
					// A busy DNS log must never turn queue backpressure into one
					// durable/event-broker write per dropped line.  Keep the queue
					// bounded and emit at most one coalesced notice per minute.
					dropped++
					s.mu.Lock()
					s.discoveryDropped++
					s.mu.Unlock()
					now := time.Now().UTC()
					if lastDropNotice.IsZero() || now.Sub(lastDropNotice) >= time.Minute {
						s.publishEvent(Event{Type: "domain.discovery", Severity: "warning", ReasonCode: "discovery_queue_full", Details: map[string]any{"dropped": dropped}})
						dropped = 0
						lastDropNotice = now
					}
				}
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
	startedAt := s.discoveryNow()
	if !s.beginDiscoveryObservation(observation.Domain, startedAt) {
		return
	}
	defer s.finishDiscoveryObservation(observation.Domain, startedAt)
	mode, _, _, _ := s.effectiveDiscoverySettings(active)
	if mode == "locked" {
		s.publishEvent(Event{Type: "domain.discovery", Severity: "info", ReasonCode: "discovery_locked", Details: map[string]any{"domain": observation.Domain, "query_type": observation.QueryType, "mode": mode}})
		return
	}
	s.mu.Lock()
	revision := s.activeRevision
	s.mu.Unlock()
	if revision == "" {
		return
	}
	now := time.Now().UTC()
	match := tspu.Match{Domain: observation.Domain, Status: "UNAVAILABLE", Evidence: "tspu_cache_deferred_observe_only"}
	// Observe-only must stay passive and bounded.  Loading the full TSPU
	// domain index here materializes a potentially 32 MiB JSON file into a
	// large Go map for every DNS observation.  On an OpenWrt router that can
	// grow well beyond the cache size and starve the controller before the
	// browser can use the API.  Classification from the already persisted
	// cache is intentionally deferred to active/suggest modes; observe-only
	// still records the observation and clearly reports classification as
	// unavailable rather than turning a DNS event into a memory-heavy job.
	if mode != "observe_only" {
		cache, err := tspu.Load(filepath.Join(active.Storage.StateDir, "tspu-cache.json"))
		if err == nil {
			if found, ok := tspu.Find(cache, observation.Domain, now); ok {
				match = found
			} else {
				match = tspu.Match{Domain: observation.Domain, Status: "NO_MATCH"}
			}
		}
	}
	if mode == "observe_only" {
		// Observe-only is intentionally passive.  It records the DNS
		// observation without materializing the large TSPU index and must not
		// invoke domainChecker (which performs active route probes).
		category := "UNKNOWN"
		if match.Status == "MATCH" {
			category = "TSPU_RESTRICTED"
		}
		s.publishEvent(Event{Type: "route.decision", Severity: "info", ReasonCode: "domain_observed_only", Details: map[string]any{
			"domain": observation.Domain, "category": category, "status": "OBSERVED", "confidence": 0,
			"classification_confidence": match.Confidence, "decision_confidence": 0,
			"tspu_status": match.Status, "query_type": observation.QueryType, "mode": mode,
			"classification": category, "classification_source": match.Source, "classification_evidence": match.Evidence,
			"classification_state": "unresolved", "probe_state": "not_run_observe_only",
			"policy_state": "observed", "service_name": observation.Domain,
		}})
		return
	}
	if s.probeBudget != nil {
		select {
		case s.probeBudget <- struct{}{}:
			defer func() { <-s.probeBudget }()
		case <-ctx.Done():
			s.publishEvent(Event{Type: "domain.discovery", Severity: "warning", ReasonCode: "probe_budget_exhausted", Details: map[string]any{"domain": observation.Domain}})
			return
		}
	}
	classification := "unknown"
	if match.Status == "MATCH" || match.Status == "STALE_MATCH" {
		classification = "TSPU_RESTRICTED"
	}
	s.publishEvent(Event{Type: "route.decision", Severity: "info", ReasonCode: "domain_verification_started", Details: map[string]any{
		"domain": observation.Domain, "category": classification, "status": "VERIFYING",
		"classification": classification, "classification_confidence": match.Confidence,
		"classification_source": match.Source, "classification_evidence": match.Evidence,
		"verification_state": "in_progress", "probe_state": "verifying", "policy_state": "observed",
		"tspu_status": match.Status, "query_type": observation.QueryType, "mode": mode,
	}})
	checkCtx, cancel := context.WithTimeout(ctx, time.Duration(maxInt(active.Policy.MaxProbeSeconds, 15))*time.Second)
	defer cancel()
	check, err := s.domainChecker(checkCtx, active, observation.Domain, "", planner.Options{
		TSPUResult: match, RouteProber: s.probeEngineFactory(active), HealthTracker: s.healthTracker,
		DecisionCache: s.domainDecisions, ActiveRevision: revision,
	})
	if err != nil {
		s.publishEvent(Event{Type: "route.decision", Severity: "warning", ReasonCode: "automatic_domain_check_failed", Details: map[string]any{"domain": observation.Domain, "error": err.Error()}})
		return
	}
	details := map[string]any{
		"domain": check.Domain, "category": check.Category, "status": check.Status,
		"confidence": check.Confidence, "decision_confidence": check.Confidence,
		"tspu_status": check.TSPUStatus, "query_type": observation.QueryType, "mode": mode,
		"classification_confidence": check.ClassificationConfidence,
		"classification_source":     check.ClassificationSource,
		"classification_evidence":   check.ClassificationEvidence,
		"classification_state":      check.ClassificationState,
		"classification_reason":     check.ClassificationReason,
		"candidate_inventory_hash":  check.CandidateInventoryHash,
		"verification_state":        check.VerificationState,
		"verification_cached":       check.Cached,
		"service":                   check.Service, "decision_duration_ms": s.discoveryNow().Sub(startedAt).Milliseconds(),
		"verification_duration_ms": checkVerificationDuration(check),
		"initial_unknown_policy":   check.InitialUnknownPolicy,
		"candidates":               discoveryCandidateDetails(check.Results),
	}
	selectedType := ""
	if check.Selected != nil {
		selectedType = check.Selected.RouteType
	}
	classification, displayName := observationClassification(check.Service, check.Category, selectedType, check.ClassificationConfidence)
	details["classification"] = classification
	details["service_name"] = displayName
	if check.ClassificationState == "" {
		details["classification_state"] = "UNKNOWN"
	}
	details["probe_state"] = plannerProbeState(check)
	details["policy_state"] = "observed"
	if mode == "suggest" {
		details["policy_state"] = "suggested"
	} else if mode == "auto_apply_verified" {
		details["policy_state"] = "pending_auto_apply"
	}
	if client := net.ParseIP(strings.TrimSpace(observation.Client)); client != nil {
		clientIP := client.String()
		details["client_ip"] = clientIP
		if client.IsLoopback() {
			system := s.provider.System(active)
			details["device_name"] = strings.TrimSpace(fmt.Sprint(system["hostname"]))
			if details["device_name"] == "" {
				details["device_name"] = "Роутер"
			}
			details["device_id"] = "router"
		}
		if privacyProvider, ok := s.provider.(platform.PrivacyDeviceProvider); ok {
			for _, device := range privacyProvider.DevicesWithPrivacy(active, true) {
				if fmt.Sprint(device["ip"]) != clientIP {
					continue
				}
				details["device_name"] = fmt.Sprint(device["name"])
				details["device_id"] = fmt.Sprint(device["id"])
				break
			}
		}
	}
	attempted := make([]string, 0, len(check.Results))
	for _, result := range check.Results {
		attempted = append(attempted, discoveryRouteLabel(result))
	}
	if len(attempted) > 0 {
		details["fallback_sequence"] = attempted
		details["fallback_performed"] = len(attempted) > 1
	}
	if check.Selected != nil {
		selectedIsDrop := check.Selected.RouteType == "drop" || check.Status == "DROP"
		if selectedIsDrop {
			// DROP is a terminal safety outcome, never a usable route assignment.
			details["route"] = ""
			details["drop_enforced"] = true
		} else {
			details["route"] = check.Selected.Route
		}
		details["route_label"] = discoveryRouteLabel(*check.Selected)
		details["route_type"] = check.Selected.RouteType
		details["path_verified"] = check.Selected.PathVerified && !selectedIsDrop
		details["route_reason"] = check.Selected.ReasonCode
		details["destination_ip"] = check.Selected.ConnectedIP
		if details["destination_ip"] == "" {
			details["destination_ip"] = check.Selected.ResolvedIP
		}
		details["route_latency_available"] = check.Selected.RouteLatencyAvailable
		if check.Selected.RouteLatencyAvailable {
			details["route_latency_ms"] = check.Selected.RouteLatencyMS
		}
		details["path_verification_duration_ms"] = check.Selected.VerificationDurationMS
		details["end_to_end_latency_available"] = check.Selected.EndToEndLatencyAvailable
		if check.Selected.EndToEndLatencyAvailable {
			details["end_to_end_latency_ms"] = check.Selected.EndToEndLatencyMS
		}
		details["selection_score"] = check.Selected.SelectionScore
		details["http_status"] = discoveryHTTPStatus(*check.Selected)
		details["tls_status"] = map[bool]string{true: "TLS OK", false: "TLS не подтверждён"}[check.Selected.TLSOK]
		details["dns_status"] = map[bool]string{true: "DNS resolved", false: "DNS не подтверждён"}[check.Selected.DNSOK]
		details["egress_interface"] = check.Selected.Interface
		details["routing_table"] = check.Selected.RouteTable
	}
	s.publishEvent(Event{Type: "route.decision", Severity: "info", ReasonCode: "domain_observed_and_classified", Details: details})
	if mode == "observe_only" {
		return
	}
	if plannerProbeState(check) == "verifying" {
		// Keep the provisional result in RAM for the live Decision Flow, but
		// do not write an unverified suggestion to bbolt. A later terminal
		// result will replace it with the durable verified/exhausted record.
		s.saveDiscoverySuggestionTransient(observation, check)
		return
	}
	if err := s.saveDiscoverySuggestion(observation, check); err != nil {
		// A suggestion that only exists in RAM is not durable evidence. Fail
		// closed before any automatic route assignment and make the storage
		// failure visible to operators instead of claiming a complete check.
		s.publishEvent(Event{Type: "domain.discovery", Severity: "warning", ReasonCode: "discovery_suggestion_persist_failed", Details: map[string]any{
			"domain": check.Domain, "error": err.Error(), "durable": false,
		}})
		return
	}
	if mode == "suggest" {
		return
	}
	if err := s.discoveryAutoAllowed(active, check); err != nil {
		s.publishEvent(Event{Type: "domain.discovery", Severity: "warning", ReasonCode: "automatic_policy_blocked", Details: map[string]any{"domain": check.Domain, "reason": err.Error(), "mode": mode}})
		return
	}
	result := s.commitAutomaticDomain(ctx, check)
	if err := s.recordDiscoveryAutoResult(result); err != nil {
		s.publishEvent(Event{Type: "domain.discovery", Severity: "warning", ReasonCode: "discovery_control_state_persist_failed", Details: map[string]any{
			"domain": check.Domain, "error": err.Error(), "durable": false,
		}})
	}
	if !result.Applied {
		s.publishEvent(Event{Type: "domain.discovery", Severity: "warning", ReasonCode: "automatic_policy_commit_failed", Details: map[string]any{"domain": check.Domain, "error": result.Reason, "rolled_back": result.RolledBack}})
	}
}

func observationClassification(service, category, selectedType string, confidence float64) (string, string) {
	if !strings.HasPrefix(service, "UNKNOWN:") {
		return "known_service", service
	}
	domain := strings.TrimPrefix(service, "UNKNOWN:")
	switch category {
	case "GEO_LOCKED":
		return "geo", domain
	case "TSPU_RESTRICTED":
		return "tspu", domain
	}
	if selectedType == "direct" && confidence > 0 {
		return "direct", domain
	}
	return "unknown", domain
}

func (s *Server) commitAutomaticDomain(ctx context.Context, check planner.DomainCheck) automaticCommitResult {
	release, failure := s.acquireMutationLease()
	if failure != nil {
		return automaticCommitResult{Reason: failure.Message}
	}
	defer func() {
		if release != nil {
			release()
		}
	}()
	if failure := s.mutationFailureNow(); failure != nil {
		return automaticCommitResult{Reason: failure.Message}
	}
	if check.Selected == nil || !planner.SelectionEvidence(*check.Selected) || check.Confidence < 0.8 {
		return automaticCommitResult{Reason: "automatic_route_assignment_requires_verified_evidence"}
	}
	active := s.currentConfig()
	if active == nil {
		return automaticCommitResult{Reason: "route_assignment_active_config_unavailable"}
	}
	route, ok := active.RouteByTag(check.Selected.Route)
	autoService, _, autoOK := automaticServiceForDecision(check)
	if !ok || !autoOK || !route.Enabled() || !config.PathAllowed(autoService, route, active.Policy) {
		return automaticCommitResult{Reason: "automatic_route_not_allowed_or_unavailable"}
	}
	if autoService.RequireNonRUEgress && route.Type != "drop" {
		country := strings.ToUpper(strings.TrimSpace(check.Selected.ExternalCountry))
		if !check.Selected.EgressConsensus || country == "" || country == "RU" {
			return automaticCommitResult{Reason: "automatic_route_egress_not_proven_non_ru"}
		}
	}
	now := s.discoveryNow()
	expires := check.ExpiresAt
	if expires.IsZero() || !now.Before(expires) {
		ttl := time.Duration(active.Policy.DomainDecisionTTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = 24 * time.Hour
		}
		expires = now.Add(ttl)
	}
	results := append([]probe.RouteResult(nil), check.Results...)
	if len(results) == 0 {
		results = []probe.RouteResult{*check.Selected}
	}
	service := strings.TrimSpace(check.Service)
	if service == "" {
		service = "UNKNOWN:" + check.Domain
	}
	revision, _ := s.activeIdentity()
	if strings.TrimSpace(revision) == "" {
		return automaticCommitResult{Reason: "route_assignment_revision_unavailable: active revision is unavailable"}
	}
	runtime := s.routeAssignmentRuntime
	if runtime == nil {
		// Persisting a decision without a runtime consumer is not an
		// assignment.  Keep the suggestion available, but fail closed instead
		// of claiming that production dataplane changed.
		return automaticCommitResult{Reason: "route_assignment_runtime_unavailable"}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	request := RouteAssignmentRequest{
		ProtocolVersion:      1,
		RequestID:            fmt.Sprintf("route-assignment-%d", now.UnixNano()),
		Generation:           revision,
		RevisionID:           revision,
		CandidateHash:        check.Selected.CandidateHash,
		ArtifactManifestHash: check.Selected.ArtifactManifestHash,
		Domain:               check.Domain,
		RouteTag:             route.Tag,
		RouteType:            route.Type,
		RouteSetID:           routeAssignmentObjectID("route:", route.Tag),
		AssignmentID:         routeAssignmentObjectID("assignment:", check.Domain),
	}
	request.MappingHash = routeAssignmentMappingHash(request)
	receipt, err := runtime.ApplyRouteAssignment(ctx, request)
	if err != nil {
		return automaticCommitResult{Reason: "route_assignment_runtime_apply_failed: " + err.Error()}
	}
	rollbackRuntime := func(reason string) automaticCommitResult {
		if err := runtime.RollbackRouteAssignment(ctx, request, receipt); err != nil {
			return automaticCommitResult{Reason: reason + "; route_assignment_runtime_rollback_failed: " + err.Error()}
		}
		return automaticCommitResult{Reason: reason, RolledBack: true}
	}
	if !receipt.Applied || !receipt.Verified || receipt.ProtocolVersion != request.ProtocolVersion ||
		receipt.RequestID != request.RequestID || receipt.Operation != "route_assignment.apply" ||
		receipt.Generation != request.Generation || receipt.RevisionID != request.RevisionID ||
		receipt.Domain != request.Domain || receipt.RouteTag != request.RouteTag || receipt.RouteType != request.RouteType ||
		receipt.RouteSetID != request.RouteSetID || receipt.AssignmentID != request.AssignmentID ||
		receipt.MappingHash != request.MappingHash {
		if receipt.Applied {
			return rollbackRuntime("route_assignment_runtime_semantic_response_invalid")
		}
		return automaticCommitResult{Reason: "route_assignment_runtime_semantic_response_invalid"}
	}
	// Prove that the newly materialized route works before recording a durable
	// decision. A pre-apply result cannot be reused: the assignment itself is
	// the mutation boundary, so the post-apply probe must observe that exact
	// route/revision.
	if s.probeEngineFactory == nil {
		return rollbackRuntime("route_assignment_post_apply_proof_unavailable")
	}
	post := s.probeEngineFactory(active).ProbeRoute(ctx, active, check.Domain, service, autoService, route)
	if post.Route != route.Tag || post.RouteType != route.Type || post.AdapterRevision != revision ||
		!planner.SelectionEvidence(post) ||
		(check.Selected.CandidateHash != "" && post.CandidateHash != check.Selected.CandidateHash) ||
		(check.Selected.ArtifactManifestHash != "" && post.ArtifactManifestHash != check.Selected.ArtifactManifestHash) ||
		(autoService.RequireNonRUEgress && route.Type != "drop" && (!post.EgressConsensus || strings.TrimSpace(post.ExternalCountry) == "" || strings.EqualFold(post.ExternalCountry, "RU"))) {
		failureResult := rollbackRuntime("route_assignment_post_apply_proof_failed")
		// A failed post-apply proof is candidate-specific evidence, not proof
		// that every already-verified route is bad.  Retry the next bounded,
		// policy-allowed candidate after the owned mapping has been rolled back.
		// Infrastructure failures (apply, semantic receipt, persistence, or
		// rollback) still return immediately and never fan out into retries.
		if failureResult.RolledBack {
			if next, found := nextAutomaticAssignmentCandidate(check, active, route.Tag); found {
				retry := check
				nextCopy := next
				retry.Selected = &nextCopy
				retry.Results = remainingRouteResults(check.Results, route.Tag)
				release()
				release = nil
				return s.commitAutomaticDomain(ctx, retry)
			}
		}
		return failureResult
	}

	decision := domaincache.Decision{
		Domain: check.Domain, ETLDPlusOne: check.ETLDPlusOne, Service: service,
		Category: check.Category, TSPUStatus: check.TSPUStatus, SelectedRoute: route.Tag,
		SelectedType: route.Type, Status: "SELECTED", Reason: "route_only_assignment",
		AdapterRevision: revision, Confidence: check.Confidence,
		ClassificationConfidence: check.ClassificationConfidence,
		ClassificationSource:     check.ClassificationSource, ClassificationEvidence: check.ClassificationEvidence,
		CandidateInventoryHash: check.CandidateInventoryHash,
		VerificationDurationMS: check.VerificationDurationMS, Results: results,
		CheckedAt: now, ExpiresAt: expires, LastUsedAt: now,
	}
	saved, err := s.domainDecisions.Save(check.Domain, decision)
	if err != nil {
		return rollbackRuntime("route_assignment_persist_failed: " + err.Error())
	}
	// Read back the exact revision-bound decision before reporting success. This
	// prevents a storage layer that returned a false-success from making the UI
	// claim a committed assignment without durable evidence.
	stored, ok, lookupErr := s.domainDecisions.Lookup(check.Domain, revision, now)
	if lookupErr != nil || !ok || stored.AdapterRevision != revision || stored.SelectedRoute != route.Tag || stored.SelectedType != route.Type ||
		(check.CandidateInventoryHash != "" && stored.CandidateInventoryHash != check.CandidateInventoryHash) {
		if lookupErr == nil {
			lookupErr = errors.New("stored route assignment does not match active revision")
		}
		cleanupErr := error(nil)
		if saved.Key != "" {
			cleanupErr = s.domainDecisions.Discard(saved.Key)
		}
		reason := "route_assignment_readback_failed: " + lookupErr.Error()
		if cleanupErr != nil {
			reason += "; decision_cleanup_failed: " + cleanupErr.Error()
		}
		return rollbackRuntime(reason)
	}
	s.mu.Lock()
	if suggestion, exists := s.discoverySuggestionMap[check.Domain]; exists {
		suggestion.PolicyState = "applied"
		suggestion.Reason = "route assignment committed"
		s.discoverySuggestionMap[check.Domain] = suggestion
	}
	s.mu.Unlock()
	if err := s.persistDiscoverySuggestions(); err != nil {
		// The route assignment and revision-bound decision are already durable;
		// suggestion metadata is auxiliary. Do not undo a verified assignment,
		// but surface the failed metadata write explicitly.
		s.publishEvent(Event{Type: "domain.discovery", Severity: "warning", ReasonCode: "route_assignment_suggestion_persist_failed", Details: map[string]any{
			"domain": check.Domain, "route": route.Tag, "error": err.Error(), "durable_assignment": true,
		}})
	}
	s.publishEvent(Event{Type: "route.decision", Severity: "info", ReasonCode: "route_assignment_committed", Details: map[string]any{
		"domain": check.Domain, "route": route.Tag, "route_type": route.Type,
		"assignment": "route_only", "post_apply_proof": true,
		"post_apply_proof_kind": "revision_bound_path_evidence", "active_revision": revision,
	}})
	_ = ctx // proof is the PathVerified result bound to the current revision.
	return automaticCommitResult{Applied: true, Reason: "route assignment committed"}
}

// nextAutomaticAssignmentCandidate returns the best remaining verified route
// that can be materialized without changing component/topology state.  The
// current route is excluded so a post-apply failure cannot recurse forever.
// The planner has already attached selection scores; sorting those scores
// preserves the same evidence-based ordering used for the initial choice.
func nextAutomaticAssignmentCandidate(check planner.DomainCheck, active *config.Config, currentRoute string) (probe.RouteResult, bool) {
	if active == nil {
		return probe.RouteResult{}, false
	}
	candidates := make([]probe.RouteResult, 0, len(check.Results))
	seen := make(map[string]struct{}, len(check.Results))
	for _, result := range check.Results {
		if result.Route == "" || result.Route == currentRoute {
			continue
		}
		if _, exists := seen[result.Route]; exists {
			continue
		}
		seen[result.Route] = struct{}{}
		if !strings.EqualFold(result.Status, "OK") || strings.EqualFold(result.Status, "REGION_BLOCK") || !result.PathVerified || !result.ServiceOK || result.RegionalBlock {
			continue
		}
		route, ok := active.RouteByTag(result.Route)
		if !ok || !route.Enabled() {
			continue
		}
		candidateCheck := check
		candidate := result
		candidateCheck.Selected = &candidate
		autoService, _, autoOK := automaticServiceForDecision(candidateCheck)
		if !autoOK || !config.PathAllowed(autoService, route, active.Policy) {
			continue
		}
		if autoService.RequireNonRUEgress && route.Type != "drop" {
			country := strings.ToUpper(strings.TrimSpace(result.ExternalCountry))
			if !result.EgressConsensus || country == "" || country == "RU" {
				continue
			}
		}
		candidates = append(candidates, result)
	}
	if len(candidates) == 0 {
		return probe.RouteResult{}, false
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].SelectionScore != candidates[j].SelectionScore {
			return candidates[i].SelectionScore < candidates[j].SelectionScore
		}
		return candidates[i].Route < candidates[j].Route
	})
	return candidates[0], true
}

func remainingRouteResults(results []probe.RouteResult, excludedRoute string) []probe.RouteResult {
	remaining := make([]probe.RouteResult, 0, len(results))
	for _, result := range results {
		if result.Route != excludedRoute {
			remaining = append(remaining, result)
		}
	}
	return remaining
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
		allowed = []string{"zapret", "smart_dns", "vless", "drop"}
	case "DIRECT_PREFERRED", "UNKNOWN", "":
		// Unknown-domain auto-routing is still a product feature, but it is
		// bounded to an already enabled route and the verified evidence gate in
		// discoveryAutoAllowed. It never grants a background task topology or
		// component mutation authority.
		category = "DIRECT_PREFERRED"
		allowed = []string{"direct", "zapret", "smart_dns", "vless", "drop"}
	default:
		return config.Service{}, "", false
	}
	// A successful Direct observation is useful evidence, but automatic
	// assignment is reserved for managed routes. Drop is a terminal safety
	// result, never a policy mapping created by discovery.
	if check.Selected.RouteType == "direct" || check.Selected.RouteType == "drop" {
		return config.Service{}, "", false
	}
	id := "auto_" + strings.NewReplacer(".", "_", "-", "_").Replace(check.ETLDPlusOne)
	return config.Service{
		Category: category, Domains: []string{check.ETLDPlusOne},
		AllowedPaths: allowed, ForbiddenPaths: forbidden, SelectedRouteTag: check.Selected.Route,
		RequireNonRUEgress: requireNonRU,
		ProbeURLs: []config.ProbeCheck{{
			Name: "automatic-web", URL: "https://" + check.Domain + "/", Required: true,
			ExpectedCodes: []int{200, 204, 301, 302, 303, 307, 308}, BodyMode: "optional",
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
	// The cache can contain tens of thousands of domains and is expensive to
	// materialise on a memory-constrained router.  Scheduling only needs the
	// validated freshness sidecar; the full index is loaded by the refresh path
	// when it is actually needed.
	cache, err := tspu.LoadFreshness(filepath.Join(active.Storage.StateDir, "tspu-cache.json"))
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
	if failure := s.mutationFailureNow(); failure != nil {
		return fmt.Errorf("mutation fenced: %s", failure.Code)
	}
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

func startupHealthDelay() time.Duration {
	var sample [2]byte
	if _, err := rand.Read(sample[:]); err != nil {
		return 45 * time.Second
	}
	// Avoid a synchronized cold-boot probe burst while keeping startup
	// responsiveness predictable on a home router.
	return 30*time.Second + time.Duration(uint16(sample[0])%61)*time.Second
}

func jitteredHealthInterval(base time.Duration) time.Duration {
	if base <= 0 {
		return 24 * time.Hour
	}
	var sample [2]byte
	if _, err := rand.Read(sample[:]); err != nil {
		return base
	}
	span := base / 10
	offset := time.Duration(float64(span) * (float64(uint16(sample[0])<<8|uint16(sample[1]))/65535*2 - 1))
	if base+offset < time.Hour {
		return time.Hour
	}
	return base + offset
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
		// Do not turn a cold boot into an immediate remote-list fetch. The
		// first refresh is deliberately delayed, while still respecting short
		// test intervals. Normal refreshes continue to use the provider/TTL
		// interval below.
		if interval < 5*time.Minute {
			return interval
		}
		return 5 * time.Minute
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
	if failure := s.mutationFailureNow(); failure != nil {
		s.publishEvent(Event{Type: "route.health", Severity: "warning", ReasonCode: "mutation_fenced", Details: map[string]any{"code": failure.Code}})
		return
	}
	active := s.currentConfig()
	if active == nil {
		// A missing active revision is a fenced control-plane state, not an
		// invitation to dereference a nil config from a background scheduler.
		s.publishEvent(Event{Type: "route.health", Severity: "warning", ReasonCode: "active_config_unavailable", Details: map[string]any{"probes_started": 0}})
		return
	}
	engine := s.probeEngineFactory(active)
	now := time.Now().UTC()
	service := health.Service{
		Tracker: s.healthTracker, Store: s.store,
		Parallelism: active.Policy.ParallelServerChecks, MaxControlServices: 3,
		ProbeBudget: s.probeBudget,
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
	if failure := s.mutationFailureNow(); failure != nil {
		return
	}
	s.runAdaptiveZapretCycle(ctx, active, engine, now)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/v1/auth/setup", s.handleSetup)
	s.mux.HandleFunc("/api/v1/auth/logout", s.requireRole(auth.RoleViewer, s.handleLogout))
	s.mux.HandleFunc("/api/v1/auth/me", s.requireRole(auth.RoleViewer, s.handleMe))
	s.mux.HandleFunc("/api/v1/overview", s.requireRole(auth.RoleViewer, s.handleOverview))
	s.mux.HandleFunc("/api/v1/onboarding", s.requireRole(auth.RoleViewer, s.handleOnboarding))
	s.mux.HandleFunc("/api/v1/topology", s.requireRole(auth.RoleViewer, s.handleTopology))
	s.mux.HandleFunc("/api/v1/devices", s.requireRole(auth.RoleViewer, s.handleDevices))
	s.mux.HandleFunc("/api/v1/services", s.requireRole(auth.RoleViewer, s.handleServices))
	s.mux.HandleFunc("/api/v1/services/classify", s.requireRole(auth.RoleAdministrator, s.handleServiceClassify))
	s.mux.HandleFunc("/api/v1/services/verify", s.requireRole(auth.RoleAdministrator, s.handleServiceVerify))
	s.mux.HandleFunc("/api/v1/services/delete", s.requireRole(auth.RoleAdministrator, s.handleServiceDelete))
	s.mux.HandleFunc("/api/v1/discovery", s.requireRole(auth.RoleViewer, s.handleDiscovery))
	s.mux.HandleFunc("/api/v1/discovery/suggestions/", s.requireRole(auth.RoleAdministrator, s.handleDiscoverySuggestionAction))
	s.mux.HandleFunc("/api/v1/discovery/configure", s.requireRole(auth.RoleAdministrator, s.handleDiscoveryConfigure))
	s.mux.HandleFunc("/api/v1/domains", s.requireRole(auth.RoleViewer, s.handleDomains))
	s.mux.HandleFunc("/api/v1/policies", s.requireRole(auth.RoleViewer, s.handlePolicies))
	s.mux.HandleFunc("/api/v1/routes", s.requireRole(auth.RoleViewer, s.handleRoutes))
	s.mux.HandleFunc("/api/v1/routes/revalidate", s.requireRole(auth.RoleAdministrator, s.handleClassifiedRevalidation))
	s.mux.HandleFunc("/api/v1/components", s.requireRole(auth.RoleViewer, s.handleComponents))
	s.mux.HandleFunc("/api/v1/components/action", s.requireRole(auth.RoleAdministrator, s.handleComponentAction))
	s.mux.HandleFunc("/api/v1/components/", s.requireRole(auth.RoleViewer, s.handleComponentStatus))
	s.mux.HandleFunc("/api/v1/traffic", s.requireRole(auth.RoleViewer, s.handleTraffic))
	s.mux.HandleFunc("/api/v1/route-health", s.requireRole(auth.RoleViewer, s.handleRouteHealth))
	s.mux.HandleFunc("/api/v1/proxies", s.requireRole(auth.RoleViewer, s.handleProxies))
	s.mux.HandleFunc("/api/v1/xray/subscription/secret", s.requireRole(auth.RoleAdministrator, s.handleXraySubscriptionSecret))
	s.mux.HandleFunc("/api/v1/xray/subscription/hwid", s.requireRole(auth.RoleAdministrator, s.handleXraySubscriptionHWID))
	s.mux.HandleFunc("/api/v1/xray/subscription/prepare", s.requireRole(auth.RoleAdministrator, s.handleXraySubscriptionPrepare))
	s.mux.HandleFunc("/api/v1/xray/manual-servers", s.requireRole(auth.RoleAdministrator, s.handleXrayManualServers))
	s.mux.HandleFunc("/api/v1/xray/pool", s.requireRole(auth.RoleViewer, s.handleXrayPool))
	s.mux.HandleFunc("/api/v1/xray/pool/settings", s.requireRole(auth.RoleAdministrator, s.handleXrayPoolSettings))
	s.mux.HandleFunc("/api/v1/xray/pool/speedtest", s.requireRole(auth.RoleAdministrator, s.handleXrayPoolSpeedTest))
	s.mux.HandleFunc("/api/v1/smart-dns", s.requireRole(auth.RoleViewer, s.handleSmartDNS))
	s.mux.HandleFunc("/api/v1/smart-dns/configure", s.requireRole(auth.RoleAdministrator, s.handleSmartDNSConfigure))
	s.mux.HandleFunc("/api/v1/smart-dns/remove", s.requireRole(auth.RoleAdministrator, s.handleSmartDNSRemove))
	s.mux.HandleFunc("/api/v1/smart-dns/reorder", s.requireRole(auth.RoleAdministrator, s.handleSmartDNSReorder))
	s.mux.HandleFunc("/api/v1/zapret", s.requireRole(auth.RoleViewer, s.handleZapret))
	s.mux.HandleFunc("/api/v1/zapret/setup/check", s.requireRole(auth.RoleAdministrator, s.handleZapretSetupCheck))
	s.mux.HandleFunc("/api/v1/zapret/setup/activate", s.requireRole(auth.RoleAdministrator, s.handleZapretSetupActivate))
	s.mux.HandleFunc("/api/v1/zapret/calibration", s.requireRole(auth.RoleAdministrator, s.handleZapretCalibration))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/runtime", s.requireRole(auth.RoleViewer, s.handleAdaptiveZapretRuntime))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/evaluate", s.requireRole(auth.RoleAdministrator, s.handleAdaptiveZapretEvaluate))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/state", s.requireRole(auth.RoleAdministrator, s.handleAdaptiveZapretState))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/pin", s.requireRole(auth.RoleAdministrator, s.handleAdaptiveZapretPin))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/unpin", s.requireRole(auth.RoleAdministrator, s.handleAdaptiveZapretUnpin))
	s.mux.HandleFunc("/api/v1/telegram", s.requireRole(auth.RoleViewer, s.handleTelegram))
	s.mux.HandleFunc("/api/v1/telegram/configure", s.requireRole(auth.RoleAdministrator, s.handleTelegramConfigure))
	s.mux.HandleFunc("/api/v1/telegram/test", s.requireRole(auth.RoleAdministrator, s.handleTelegramTest))
	s.mux.HandleFunc("/api/v1/external-socks", s.requireRole(auth.RoleViewer, s.handleExternalSOCKS))
	s.mux.HandleFunc("/api/v1/external-socks/check", s.requireRole(auth.RoleAdministrator, s.handleExternalSOCKSCheck))
	s.mux.HandleFunc("/api/v1/external-socks/activate", s.requireRole(auth.RoleAdministrator, s.handleExternalSOCKSActivate))
	s.mux.HandleFunc("/api/v1/tgws", s.requireRole(auth.RoleViewer, s.handleTGWS))
	s.mux.HandleFunc("/api/v1/tgws/configure", s.requireRole(auth.RoleAdministrator, s.handleTGWSConfigure))
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
	reveal := r.URL.Query().Get("privacy") != "hidden"
	if provider, ok := s.provider.(platform.PrivacyTopologyProvider); ok {
		writeData(w, r, provider.TopologyWithPrivacy(s.currentConfig(), reveal))
		return
	}
	writeData(w, r, s.provider.Topology(s.currentConfig()))
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	reveal := r.URL.Query().Get("privacy") != "hidden"
	if provider, ok := s.provider.(platform.PrivacyDeviceProvider); ok {
		writeData(w, r, provider.DevicesWithPrivacy(s.currentConfig(), reveal))
		return
	}
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
		item := map[string]any{
			"id": id, "category": svc.Category, "domains": svc.Domains,
			"allowed_paths": svc.AllowedPaths, "forbidden_paths": svc.ForbiddenPaths,
			"selected_route_tag": svc.SelectedRouteTag,
			"probe_count":        len(svc.ProbeURLs), "require_non_ru_egress": svc.RequireNonRUEgress,
			"source": "configured", "applied": true,
			// A persisted policy is not proof that its path was checked against
			// the current network. Keep configuration and runtime evidence
			// separate so YouTube (and every other service) cannot appear
			// falsely verified merely because a rule was saved.
			"status": "CONFIGURED", "classification_state": "configured",
			"probe_state": "not_checked", "verification_state": "not_checked",
			"verification_reason": "policy_applied_path_not_verified", "policy_state": "applied",
		}
		matrix := s.serviceCandidateMatrix(id, svc)
		item["candidate_matrix"] = matrix
		item["eligible_route_types"] = uniqueRouteTypes(matrix)
		if proof, ok := s.latestConfiguredServiceProof(id, svc, time.Now().UTC()); ok {
			item["status"] = "VERIFIED"
			item["probe_state"] = "verified_candidate"
			item["verification_state"] = "verified"
			item["verification_reason"] = "path_verified"
			item["checked_at"] = proof.CheckedAt
			item["latest_checked_at"] = proof.CheckedAt
			item["verification_route_latency_ms"] = proof.RouteLatencyMS
			item["verification_route_latency_available"] = proof.RouteLatencyAvailable
			item["verification_end_to_end_latency_available"] = proof.EndToEndLatencyAvailable
			if proof.EndToEndLatencyAvailable {
				item["verification_end_to_end_latency_ms"] = proof.EndToEndLatencyMS
			}
			if svc.SelectedRouteTag == "" {
				item["selected_route_tag"] = proof.Route
			}
		}
		items = append(items, item)
	}
	discoveryMode, _, _, _ := s.effectiveDiscoverySettings(cfg)
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
			selectedRoute := decision.SelectedRoute
			selectedType := decision.SelectedType
			status := decision.Status
			confidence := decision.Confidence
			if selectedType != "" && !routeTypeInOrder(allowedPaths, selectedType) {
				selectedRoute = ""
				selectedType = ""
				status = "STALE_POLICY_MISMATCH"
				confidence = 0
			}
			classificationConfidence := decision.ClassificationConfidence
			classificationState := "unresolved"
			if classificationConfidence > 0 || category == "GEO_LOCKED" || category == "TSPU_RESTRICTED" {
				classificationState = "classified"
			}
			// A cached/observed decision can carry a selected route without
			// carrying complete path evidence (for example after an interrupted
			// verification or a legacy cache record). Never turn that route ID
			// into a green "verified" state unless the matching result proves
			// service success and PathVerified.
			probeState := automaticDecisionProbeState(decision, selectedRoute, selectedType, status)
			policyState := "observed"
			if discoveryMode == "suggest" {
				policyState = "suggested"
			}
			classification, displayName := observationClassification(decision.Service, category, selectedType, classificationConfidence)
			items = append(items, map[string]any{
				"id":                        decision.Service,
				"display_name":              displayName,
				"classification":            classification,
				"category":                  category,
				"domains":                   []string{decision.Domain},
				"allowed_paths":             allowedPaths,
				"forbidden_paths":           forbiddenPaths,
				"selected_route_tag":        selectedRoute,
				"selected_route_type":       selectedType,
				"status":                    status,
				"confidence":                confidence,
				"decision_confidence":       confidence,
				"classification_confidence": classificationConfidence,
				"classification_source":     decision.ClassificationSource,
				"classification_evidence":   decision.ClassificationEvidence,
				"checked_at":                decision.CheckedAt,
				"expires_at":                decision.ExpiresAt,
				"source":                    "automatic",
				"applied":                   false,
				"kind":                      "discovery_observation",
				"classification_state":      classificationState,
				"probe_state":               probeState,
				"policy_state":              policyState,
				"candidate_matrix":          discoveryCandidateDetails(decision.Results),
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

func automaticDecisionProbeState(decision domaincache.Decision, selectedRoute, selectedType, status string) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "VERIFYING", "PROBING", "WAITING", "IN_PROGRESS":
		return "verifying"
	case "NO_SAFE_ROUTE":
		if len(decision.Results) == 0 {
			return "verifying"
		}
		for _, result := range decision.Results {
			if !decisionResultTerminal(result.Status) {
				return "verifying"
			}
		}
		return "no_safe_route"
	case "SELECTED", "DROP":
		if selectedRoute == "" {
			return "verifying"
		}
		for _, result := range decision.Results {
			if result.Route == selectedRoute && result.RouteType == selectedType && planner.SelectionEvidence(result) {
				return "verified_candidate"
			}
		}
		return "verifying"
	default:
		return "not_checked"
	}
}

func decisionResultTerminal(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "FAIL", "OK", "DEGRADED", "NOT_CONFIGURED", "NOT_APPLICABLE", "UNVERIFIED", "RU_EXIT", "REGION_BLOCK", "SUSPECTED_TSPU", "DROP", "TIMEOUT", "ERROR":
		return true
	default:
		return false
	}
}

func routeTypeInOrder(order []string, routeType string) bool {
	for _, item := range order {
		if item == routeType {
			return true
		}
	}
	return false
}

type serviceClassifyRequest struct {
	Domain                     string   `json:"domain"`
	Category                   string   `json:"category"`
	AllowedPaths               []string `json:"allowed_paths,omitempty"`
	BaseVersion                int64    `json:"base_version"`
	AllowDisableFlowOffloading bool     `json:"allow_disable_flow_offloading,omitempty"`
}

func serviceForClassifyRequest(request serviceClassifyRequest) (string, config.Service, error) {
	domain, err := tspu.NormalizeDomain(request.Domain)
	if err != nil {
		return "", config.Service{}, err
	}
	category := strings.ToUpper(strings.TrimSpace(request.Category))
	service := config.Service{
		Domains: []string{domain},
		ProbeURLs: []config.ProbeCheck{{
			Name: "https", URL: "https://" + domain + "/", Required: true,
			ExpectedCodes: []int{200, 204, 301, 302, 303, 307, 308}, BodyMode: "optional",
		}},
	}
	switch category {
	case "GEO_LOCKED":
		service.Category = category
		service.AllowedPaths = []string{"smart_dns", "vless", "drop"}
		service.ForbiddenPaths = []string{"direct", "zapret"}
		service.RequireNonRUEgress = true
	case "TSPU_RESTRICTED":
		service.Category = category
		service.AllowedPaths = []string{"zapret", "smart_dns", "vless", "drop"}
	case "DIRECT_PREFERRED":
		service.Category = category
		service.AllowedPaths = []string{"direct", "zapret", "smart_dns", "vless", "drop"}
	case "DIRECT_ONLY":
		service.Category = category
		service.AllowedPaths = []string{"direct"}
		service.ForbiddenPaths = []string{"zapret", "smart_dns", "vless", "drop"}
	case "BLOCKED":
		service.Category = category
		service.AllowedPaths = []string{"drop"}
		service.ForbiddenPaths = []string{"direct", "zapret", "smart_dns", "vless"}
	default:
		return "", config.Service{}, fmt.Errorf("category must be GEO_LOCKED, TSPU_RESTRICTED, DIRECT_PREFERRED, DIRECT_ONLY or BLOCKED")
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
			if category == "DIRECT_ONLY" && path != "direct" {
				return "", config.Service{}, fmt.Errorf("DIRECT_ONLY can only use direct")
			}
			if category == "BLOCKED" && path != "drop" {
				return "", config.Service{}, fmt.Errorf("BLOCKED can only use drop")
			}
			seen[path] = true
			service.AllowedPaths = append(service.AllowedPaths, path)
		}
	}
	return category, service, nil
}

type serviceVerifyRequest struct {
	ServiceID string `json:"service_id,omitempty"`
	Domain    string `json:"domain,omitempty"`
}

// handleServiceVerify performs a read-only path check for an already persisted
// service. It deliberately does not create a ChangeSet or call the adapter:
// the user is asking "does the current rule work?", not asking to mutate the
// dataplane. The resulting probe evidence is stored separately so the next
// services read can show the last verified state without treating policy
// persistence as proof.
func (s *Server) handleServiceVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	var request serviceVerifyRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	serviceID, service, domain, err := s.configuredServiceForVerification(request)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_service", err.Error())
		return
	}
	check, verifyErr := s.selectVerifiedServiceRoute(r.Context(), serviceID, serviceWithVerificationDomain(service, domain))
	persisted := 0
	if s.store != nil {
		for _, result := range check.Results {
			if err := s.store.StoreProbeResult(result); err == nil {
				persisted++
			}
		}
	}
	state := check.VerificationState
	if state == "" {
		switch {
		case check.Selected != nil && check.Selected.PathVerified:
			state = "verified"
		case len(check.Results) > 0:
			state = "in_progress"
		default:
			state = "error"
		}
	}
	response := map[string]any{
		"service_id": serviceID, "domain": domain, "status": check.Status,
		"verification_state": state, "reason": check.Reason,
		"classification_confidence": check.ClassificationConfidence,
		"classification_state":      check.ClassificationState, "classification_reason": check.ClassificationReason,
		"checked_at": check.CheckedAt, "verification_duration_ms": check.VerificationDurationMS,
		"selected_route_tag": "", "selected_route_type": "", "path_verified": false,
		"candidates": discoveryCandidateDetails(check.Results), "evidence_persisted": persisted,
	}
	if check.Selected != nil {
		response["selected_route_tag"] = check.Selected.Route
		response["selected_route_type"] = check.Selected.RouteType
		response["path_verified"] = check.Selected.PathVerified
		if check.Selected.RouteLatencyAvailable {
			response["route_latency_ms"] = check.Selected.RouteLatencyMS
		}
		response["route_latency_available"] = check.Selected.RouteLatencyAvailable
		response["end_to_end_latency_available"] = check.Selected.EndToEndLatencyAvailable
		if check.Selected.EndToEndLatencyAvailable {
			response["end_to_end_latency_ms"] = check.Selected.EndToEndLatencyMS
		}
		response["selection_score"] = check.Selected.SelectionScore
	}
	if verifyErr != nil {
		response["error_code"] = "route_verification_failed"
		response["error"] = verifyErr.Error()
	}
	writeData(w, r, response)
}

func serviceWithVerificationDomain(service config.Service, domain string) config.Service {
	service.Domains = []string{domain}
	return service
}

func (s *Server) configuredServiceForVerification(request serviceVerifyRequest) (string, config.Service, string, error) {
	cfg := s.currentConfig()
	if cfg == nil {
		return "", config.Service{}, "", errors.New("active configuration is unavailable")
	}
	serviceID := strings.TrimSpace(request.ServiceID)
	service, ok := cfg.Services[serviceID]
	if serviceID != "" && !ok {
		return "", config.Service{}, "", errors.New("configured service was not found")
	}
	domain := strings.TrimSpace(request.Domain)
	if domain == "" && len(service.Domains) > 0 {
		domain = service.Domains[0]
	}
	normalized, err := tspu.NormalizeDomain(domain)
	if err != nil {
		return "", config.Service{}, "", errors.New("a valid service domain is required")
	}
	if serviceID == "" {
		serviceID = cfg.ServiceForDomain(normalized)
		if serviceID == "" {
			return "", config.Service{}, "", errors.New("configured service was not found for this domain")
		}
		service, ok = cfg.Services[serviceID]
		if !ok {
			return "", config.Service{}, "", errors.New("configured service was not found")
		}
	}
	belongs := false
	for _, candidate := range service.Domains {
		if normalizedCandidate, normalizeErr := tspu.NormalizeDomain(candidate); normalizeErr == nil && normalizedCandidate == normalized {
			belongs = true
			break
		}
	}
	if !belongs {
		return "", config.Service{}, "", errors.New("domain is not part of the configured service")
	}
	return serviceID, service, normalized, nil
}

const configuredServiceProofFreshness = 15 * time.Minute

func (s *Server) latestConfiguredServiceProof(serviceID string, service config.Service, now time.Time) (probe.RouteResult, bool) {
	if s == nil || s.store == nil {
		return probe.RouteResult{}, false
	}
	items, err := s.store.ListProbeResults(500)
	if err != nil {
		return probe.RouteResult{}, false
	}
	for _, item := range items {
		if item.Service != serviceID || !serviceDomainContains(service, item.Domain) || !planner.SelectionEvidence(item) {
			continue
		}
		if service.SelectedRouteTag != "" && item.Route != service.SelectedRouteTag {
			continue
		}
		checkedAt, parseErr := time.Parse(time.RFC3339, item.CheckedAt)
		if parseErr != nil || checkedAt.After(now.Add(time.Minute)) || now.Sub(checkedAt) > configuredServiceProofFreshness {
			continue
		}
		return item, true
	}
	return probe.RouteResult{}, false
}

func serviceDomainContains(service config.Service, domain string) bool {
	normalized, err := tspu.NormalizeDomain(domain)
	if err != nil {
		return false
	}
	for _, candidate := range service.Domains {
		if value, normalizeErr := tspu.NormalizeDomain(candidate); normalizeErr == nil && value == normalized {
			return true
		}
	}
	return false
}

func (s *Server) handleServiceClassify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	if failure := s.mutationFailureNow(); failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
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
	check, err := s.selectVerifiedServiceRoute(r.Context(), id, service)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "route_verification_failed", err.Error())
		return
	}
	service.SelectedRouteTag = check.Selected.Route
	operations := []ChangeOp{{Type: "set", Path: "/services/" + id, Value: service}}
	if request.AllowDisableFlowOffloading {
		operations = append(operations, ChangeOp{Type: "set", Path: "/openwrt/flow_offloading_policy", Value: "disable"})
	}
	change, err := s.createDraftChange(
		"Change route class for "+domain,
		"Persist the selected route class for an observed domain",
		request.BaseVersion,
		operations,
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
	writeData(w, r, map[string]any{
		"change": change, "domain": domain, "category": category,
		"selected_route_tag": check.Selected.Route, "selected_route_type": check.Selected.RouteType,
		"path_verified": check.Selected.PathVerified, "selection_state": serviceRouteSelectionState(check.Selected),
		"candidates": discoveryCandidateDetails(check.Results),
	})
}

func (s *Server) selectVerifiedServiceRoute(ctx context.Context, serviceID string, service config.Service) (planner.DomainCheck, error) {
	active := s.currentConfig()
	if active == nil {
		return planner.DomainCheck{}, errors.New("active configuration is unavailable")
	}
	raw, err := json.Marshal(active)
	if err != nil {
		return planner.DomainCheck{}, fmt.Errorf("copy active configuration: %w", err)
	}
	var candidate config.Config
	if err := json.Unmarshal(raw, &candidate); err != nil {
		return planner.DomainCheck{}, fmt.Errorf("copy active configuration: %w", err)
	}
	if candidate.Services == nil {
		candidate.Services = map[string]config.Service{}
	}
	candidate.Services[serviceID] = service

	domain := service.Domains[0]
	now := time.Now().UTC()
	match := tspu.Match{Domain: domain, Status: "NO_MATCH"}
	if service.Category == "TSPU_RESTRICTED" {
		match.Status = "MATCH"
	} else if cache, loadErr := tspu.Load(filepath.Join(active.Storage.StateDir, "tspu-cache.json")); loadErr == nil {
		if found, ok := tspu.Find(cache, domain, now); ok {
			match = found
		}
	}

	revision, _ := s.activeIdentity()
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(maxInt(active.Policy.MaxProbeSeconds, 15))*time.Second)
	defer cancel()
	var routeProber planner.RouteProber
	if s.probeEngineFactory != nil {
		routeProber = s.probeEngineFactory(&candidate)
	}
	check, err := s.domainChecker(probeCtx, &candidate, domain, serviceID, planner.Options{
		TSPUResult: match, FullCheck: true, RouteProber: routeProber, HealthTracker: s.healthTracker,
		ActiveRevision: revision,
	})
	if err != nil {
		return check, fmt.Errorf("route preflight failed: %w", err)
	}
	if check.Selected == nil {
		check.Selected = candidateRequiringGuardedApply(check.Results, service.AllowedPaths, candidate.Policy, s.healthTracker)
		if check.Selected != nil {
			check.Status = "CANDIDATE_REQUIRES_APPLY"
			check.Reason = "candidate_transport_verified_requires_bound_path_apply"
		}
	}
	if check.Selected == nil ||
		(check.Selected.ReasonCode == "route_not_bound_to_verification_plan" && !guardedApplyCandidateEvidence(*check.Selected)) ||
		(check.Selected.ReasonCode != "route_not_bound_to_verification_plan" && !planner.SelectionEvidence(*check.Selected)) {
		return check, errors.New("no safe route passed DNS, service and data-path verification")
	}
	if _, ok := candidate.RouteByTag(check.Selected.Route); !ok {
		return check, fmt.Errorf("verified route %q is not part of the active configuration", check.Selected.Route)
	}
	return check, nil
}

func candidateRequiringGuardedApply(results []probe.RouteResult, allowedPaths []string, policy config.Policy, health *probe.HealthTracker) *probe.RouteResult {
	allowed := make(map[string]struct{}, len(allowedPaths))
	for _, routeType := range allowedPaths {
		allowed[routeType] = struct{}{}
	}
	var best *probe.RouteResult
	for i := range results {
		result := results[i]
		if _, ok := allowed[result.RouteType]; !ok || result.PathVerified || result.ReasonCode != "route_not_bound_to_verification_plan" {
			continue
		}
		if !guardedApplyCandidateEvidence(result) {
			continue
		}
		if best == nil || planner.ScoreRouteResult(result, policy, health) < planner.ScoreRouteResult(*best, policy, health) ||
			(planner.ScoreRouteResult(result, policy, health) == planner.ScoreRouteResult(*best, policy, health) && result.Route < best.Route) {
			candidate := result
			best = &candidate
		}
	}
	return best
}

// guardedApplyCandidateEvidence is intentionally separate from
// planner.SelectionEvidence: this candidate has passed DNS/transport/service
// checks but has not yet been bound to a live route path. It may only proceed
// to the explicit guarded-apply workflow, never to automatic assignment.
func guardedApplyCandidateEvidence(result probe.RouteResult) bool {
	return result.ReasonCode == "route_not_bound_to_verification_plan" && !result.PathVerified &&
		result.DNSOK && result.TransportOK && result.ServiceOK && !result.RegionalBlock &&
		!result.SuspectedTSPU && !result.AuthenticationRequired && !result.WAFOrRateLimit && !result.Simulation
}

func serviceRouteSelectionState(result *probe.RouteResult) string {
	if result == nil {
		return "no_safe_route"
	}
	if result.PathVerified {
		return "path_verified"
	}
	return "candidate_verified_requires_apply"
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
	active := s.currentConfig()
	if active == nil {
		writeError(w, r, http.StatusServiceUnavailable, "active_config_unavailable", "Smart DNS state is unavailable until a committed config is restored")
		return
	}
	routes := smartDNSRoutesInOrder(filterRoutes(active, "smart_dns"))
	healthIntervalSeconds := 300
	if active != nil && active.Policy.HealthCheckIntervalSeconds > 0 {
		healthIntervalSeconds = active.Policy.HealthCheckIntervalSeconds
	}
	healthByTag := map[string]probe.RouteHealth{}
	for _, item := range s.healthTracker.Snapshot() {
		if item.RouteType == "smart_dns" {
			healthByTag[item.RouteTag] = item
		}
	}
	items := make([]map[string]any, 0, len(routes))
	ready := 0
	configured := 0
	now := time.Now().UTC()
	for order, route := range routes {
		health, observed := healthByTag[route.Tag]
		healthFresh := observed && smartDNSHealthFresh(health, now, healthIntervalSeconds)
		freshness := "stale"
		if healthFresh {
			freshness = "fresh"
		}
		status := route.Status
		resolverConfigured := route.DNSServer != "" && !strings.Contains(route.DNSServer, "PLACEHOLDER")
		validation, primaryValidationOK := s.loadSmartDNSValidation(route.DNSServer)
		fallbackValidation, fallbackValidationOK := s.loadSmartDNSValidation(route.DNSFallbackServer)
		validationOK := primaryValidationOK && (route.DNSFallbackServer == "" || fallbackValidationOK)
		resolverReady, nextStatus := smartDNSResolverState(route, health, healthFresh, validationOK)
		status = nextStatus
		if observed && health.State == "healthy" && !healthFresh && !validationOK && !route.Disabled && resolverConfigured {
			status = "stale"
		}
		if resolverReady {
			ready++
		}
		if !route.Disabled && resolverConfigured {
			configured++
		}
		item := map[string]any{
			"tag": route.Tag, "status": status, "enabled": !route.Disabled,
			"name":                   smartDNSRouteName(route, order+1),
			"resolver_configured":    resolverConfigured,
			"order":                  order + 1,
			"connect_to_resolved_ip": route.ConnectToResolvedIP,
			"validation_complete":    validationOK,
			"health":                 health,
			"freshness":              freshness,
			"health_fresh":           healthFresh,
			"kind":                   "conditional_dns",
			"vpn":                    false,
		}
		if resolverConfigured {
			host, port, _ := net.SplitHostPort(route.DNSServer)
			item["resolver_ip"] = host
			item["resolver_port"] = port
			if primaryValidationOK {
				item["last_validation"] = validation
			}
			if route.DNSFallbackServer != "" {
				fallbackHost, fallbackPort, _ := net.SplitHostPort(route.DNSFallbackServer)
				item["fallback_resolver_ip"] = fallbackHost
				item["fallback_resolver_port"] = fallbackPort
				if fallbackValidationOK {
					item["fallback_validation"] = fallbackValidation
				}
			}
		}
		items = append(items, item)
	}
	writeData(w, r, map[string]any{
		"configured":          configured > 0,
		"configured_count":    configured,
		"ready":               ready,
		"automatic_operation": s.smartDNSAutomaticOperation(),
		"routes":              items,
		"selection_semantics": "route types are eligibility constraints; every available candidate is probed and the winner is selected from hard-filtered evidence",
		"success_contract":    []string{"safe DNS answer", "connection to returned address", "content check", "egress check when required"},
		"route_semantics":     "conditional DNS; not a VPN or tunnel",
	})
}

// smartDNSAutomaticOperation exposes the bounded product flow without
// leaking its internal ChangeSet operations. The UI can therefore distinguish
// "being applied" from a resolver that is merely configured but idle.
func (s *Server) smartDNSAutomaticOperation() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var selected *ChangeSet
	for _, change := range s.changes {
		if !change.AutoApply || !isSmartDNSAutoChangeTitle(change.Title) {
			continue
		}
		switch change.State {
		case "draft", "validated", "applying", "awaiting_confirmation", "committing", "recovery_required", "requires_device", "failed", "rolled_back":
		default:
			continue
		}
		candidate := change
		if selected == nil || candidate.UpdatedAt > selected.UpdatedAt {
			selected = &candidate
		}
	}
	if selected == nil {
		return nil
	}
	return map[string]any{
		"id":                  selected.ID,
		"state":               selected.State,
		"updated_at":          selected.UpdatedAt,
		"adapter_status":      selected.AdapterStatus,
		"management_verified": selected.ManagementVerified,
		"data_plane_verified": selected.DataPlaneVerified,
		"recovery_required":   selected.State == "recovery_required",
		"requires_device":     selected.State == "requires_device",
	}
}

func isSmartDNSAutoChangeTitle(title string) bool {
	switch title {
	case "Configure Smart DNS resolvers", "Remove Smart DNS resolver", "Reorder Smart DNS resolvers":
		return true
	default:
		return false
	}
}

// smartDNSHealthFresh prevents a persisted healthy result from becoming an
// unbounded authorization to use a resolver.  A resolver may be idle and
// selectable on the basis of a separate, still-valid validation record; the
// health-cycle result itself must remain within two configured check intervals.
func smartDNSHealthFresh(health probe.RouteHealth, now time.Time, intervalSeconds int) bool {
	if health.LastCheckedAt.IsZero() || now.Before(health.LastCheckedAt) {
		return false
	}
	interval := time.Duration(intervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	maxAge := 2 * interval
	if maxAge < 2*time.Minute {
		maxAge = 2 * time.Minute
	}
	return now.Sub(health.LastCheckedAt) <= maxAge
}

func smartDNSResolverState(route config.Route, health probe.RouteHealth, observed, validationOK bool) (bool, string) {
	if route.Disabled || route.DNSServer == "" || strings.Contains(route.DNSServer, "PLACEHOLDER") {
		return false, route.Status
	}
	if observed && health.State == "healthy" {
		return true, "healthy"
	}
	// A resolver cannot have a bound dataplane proof until a service policy
	// actually uses it. Fresh transport/content validation makes it selectable
	// for a guarded transaction; confirmation still requires PathVerified.
	if validationOK && (!observed || health.LastReason == "route_not_bound_to_verification_plan") {
		return true, "validated_idle"
	}
	if observed {
		return false, health.State
	}
	return false, route.Status
}

type smartDNSConfigureRequest struct {
	BaseVersion int64                   `json:"base_version"`
	Resolvers   []smartDNSResolverInput `json:"resolvers,omitempty"`
	Endpoints   []string                `json:"endpoints,omitempty"`
	TestDomain  string                  `json:"test_domain"`
	AutoApply   bool                    `json:"auto_apply,omitempty"`
}

type smartDNSResolverInput struct {
	Name         string `json:"name,omitempty"`
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	FallbackIP   string `json:"fallback_ip,omitempty"`
	FallbackPort int    `json:"fallback_port,omitempty"`
}

func (s *Server) handleSmartDNSConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	if failure := s.mutationFailureNow(); failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	var request smartDNSConfigureRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	active := s.currentConfig()
	if active == nil {
		writeError(w, r, http.StatusServiceUnavailable, "active_config_unavailable", "Smart DNS cannot be configured without a committed config")
		return
	}
	if request.BaseVersion <= 0 {
		writeError(w, r, http.StatusBadRequest, "invalid_base_version", "base_version must be positive")
		return
	}
	testDomain, err := tspu.NormalizeDomain(request.TestDomain)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_smart_dns_test_domain", "test_domain must be a DNS name used for the HTTP/TLS check")
		return
	}
	request.TestDomain = testDomain
	inputs := append([]smartDNSResolverInput{}, request.Resolvers...)
	for _, endpoint := range request.Endpoints {
		inputs = append(inputs, smartDNSResolverInput{IP: endpoint})
	}
	routes, cards, err := smartDNSRoutesForInputs(active, inputs)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_smart_dns_endpoint", err.Error())
		return
	}
	validationResults := make([]probe.SmartDNSValidationResult, 0, len(cards)*2)
	validationFailures := make([]string, 0)
	for _, card := range cards {
		cardEndpoints := []string{card.Primary}
		if card.Fallback != "" {
			cardEndpoints = append(cardEndpoints, card.Fallback)
		}
		for _, endpoint := range cardEndpoints {
			validationContext, cancel := context.WithTimeout(r.Context(), 25*time.Second)
			result, validationErr := s.smartDNSValidator(validationContext, endpoint, request.TestDomain)
			cancel()
			if validationErr != nil {
				validationFailures = append(validationFailures, fmt.Sprintf("%s: %v", endpoint, validationErr))
				continue
			}
			validationResults = append(validationResults, result)
		}
	}
	if len(validationFailures) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "smart_dns_validation_failed", strings.Join(validationFailures, "; "))
		return
	}
	for _, result := range validationResults {
		if err := s.saveSmartDNSValidation(result.Endpoint, request.TestDomain, result); err != nil {
			writeError(w, r, http.StatusInternalServerError, "smart_dns_validation_store_failed", err.Error())
			return
		}
	}
	operations := []ChangeOp{{Type: "set", Path: "/routes", Value: routes}}
	session := currentSession(r)
	change, err := s.createDraftChangeWithOptions("Configure Smart DNS resolvers", "Validate resolvers before using VPN fallback", request.BaseVersion, operations, session.User, request.AutoApply)
	if err != nil {
		if errors.Is(err, errBaseVersionConflict) {
			writeError(w, r, http.StatusConflict, "base_version_conflict", "base_version does not match current revision")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "smart_dns_change_failed", err.Error())
		return
	}
	autoApplyStarted := request.AutoApply && s.startAutoApplyChange(change.ID)
	writeData(w, r, map[string]any{
		"change": change, "endpoint_count": len(cards), "validations": validationResults,
		"auto_apply_requested": request.AutoApply, "auto_apply_started": autoApplyStarted,
	})
}

func normalizeSmartDNSEndpoint(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("Smart DNS endpoint is empty")
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		if parsed := net.ParseIP(value); parsed != nil {
			host, port = value, "53"
		} else {
			return "", errors.New("Smart DNS endpoint must be an IP address with an optional port")
		}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !netpolicy.PublicResolverAddr(ip) {
		return "", errors.New("Smart DNS endpoint must use a public, non-bogon unicast IP address")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return "", errors.New("Smart DNS endpoint port must be between 1 and 65535")
	}
	return net.JoinHostPort(ip.Unmap().String(), strconv.FormatUint(parsedPort, 10)), nil
}
func (s *Server) handleZapret(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentConfig()
	profiles, fallback, assignments := zapretProfileStatus(cfg)
	writeData(w, r, map[string]any{
		"status":              zapretSetupStatus(cfg),
		"routes":              filterRoutes(cfg, "zapret"),
		"activation_mode":     cfg.Zapret.ActivationMode,
		"provider_pinned":     cfg.Zapret.ProviderSource != "" && cfg.Zapret.ProviderVersion != "" && cfg.Zapret.BinarySHA256 != "",
		"provider_version":    cfg.Zapret.ProviderVersion,
		"active_profile":      profiles,
		"fallback_profile":    fallback,
		"profile_assignments": assignments,
	})
}

// zapretProfileStatus exposes the actual selected catalog profile rather than
// leaking the internal strategy enum. When an adaptive catalog is available,
// the next allowed profile is the declared fallback for that bundle. Missing
// catalog metadata is represented as an unavailable profile, never guessed.
func zapretProfileStatus(cfg *config.Config) (map[string]any, map[string]any, []map[string]any) {
	empty := map[string]any{}
	if cfg == nil {
		return empty, empty, nil
	}
	profiles := map[string]zapret.Profile{}
	bundles := map[string]zapret.ServiceBundle{}
	if path := strings.TrimSpace(cfg.Zapret.AdaptiveCatalogFile); path != "" {
		profileCatalog, bundleCatalog, err := zapret.LoadCatalogFile(path)
		if err == nil {
			// Catalog has no public iterator by design. Resolve only IDs named by
			// the persisted assignments; unknown IDs remain visibly unresolved.
			for _, assignment := range cfg.Zapret.AdaptiveAssignments {
				if profile, ok := profileCatalog.Lookup(assignment.ProfileID); ok {
					profiles[assignment.ProfileID] = profile
				}
				if bundle, ok := bundleCatalog.Lookup(assignment.BundleID); ok {
					bundles[assignment.BundleID] = bundle
				}
			}
		}
	}
	assignments := make([]map[string]any, 0, len(cfg.Zapret.AdaptiveAssignments))
	var active, fallback map[string]any
	for _, assignment := range cfg.Zapret.AdaptiveAssignments {
		profile, profileOK := profiles[assignment.ProfileID]
		activeView := map[string]any{"bundle_id": assignment.BundleID, "profile_id": assignment.ProfileID, "available": profileOK}
		if profileOK {
			activeView["profile_name"] = profile.Name
		}
		assignments = append(assignments, activeView)
		if active == nil {
			active = activeView
		}
		bundle, bundleOK := bundles[assignment.BundleID]
		if !bundleOK {
			continue
		}
		for index, profileID := range bundle.AllowedProfiles {
			if profileID != assignment.ProfileID || index+1 >= len(bundle.AllowedProfiles) {
				continue
			}
			nextID := bundle.AllowedProfiles[index+1]
			next, nextOK := profiles[nextID]
			fallback = map[string]any{"bundle_id": assignment.BundleID, "profile_id": nextID, "available": nextOK}
			if nextOK {
				fallback["profile_name"] = next.Name
			}
			break
		}
		if fallback != nil {
			break
		}
	}
	if active == nil && strings.TrimSpace(cfg.Zapret.Strategy) != "" {
		active = map[string]any{"profile_id": cfg.Zapret.Strategy, "available": false}
	}
	if fallback == nil {
		fallback = empty
	}
	if active == nil {
		active = empty
	}
	return active, fallback, assignments
}
func (s *Server) handleTelegram(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	writeData(w, r, map[string]any{
		"notifications": s.telegramNotifier.Status(),
		"event_types":   telegramnotify.SupportedEventTypes,
		"transport":     map[string]any{"type": "external_socks", "managed_by": "external", "core_routing_dependency": false},
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
	// Event history is fail-closed: callers must explicitly opt in to an
	// address-revealing view.  Secrets are redacted in both views.
	hideAddresses := r.URL.Query().Get("privacy") != "visible"
	for _, event := range byID {
		event.Details = sanitizeEventDetailsForPrivacy(event.Details, hideAddresses)
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
			"telegram":                       s.telegramNotifier.Status(),
			"webhook_secret_path_configured": strings.TrimSpace(cfg.Notifications.HTTPSWebhookSecretFile) != "",
			"dedupe_seconds":                 cfg.Notifications.DedupeSeconds,
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
		if failure := mutationFailureFromError(err); failure != nil {
			writeError(w, r, failure.Status, failure.Code, failure.Message)
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
		mutationRelease, mutationFailure := s.acquireMutationLease()
		if mutationFailure != nil {
			writeError(w, r, mutationFailure.Status, mutationFailure.Code, mutationFailure.Message)
			return
		}
		defer mutationRelease()
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
	// EventSource cannot attach the normal privacy header, so the query is the
	// explicit contract.  Missing/invalid privacy is hidden by default.
	hideAddresses := r.URL.Query().Get("privacy") != "visible"
	writePrivacyEvent := func(ev Event) {
		writeSSE(w, sanitizeEventForPrivacy(ev, hideAddresses))
	}
	for _, ev := range s.broker.Recent(afterID, 20) {
		writePrivacyEvent(ev)
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
			writePrivacyEvent(ev)
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
	s.mu.Lock()
	activeRevision := s.activeRevision
	s.mu.Unlock()
	if activeRevision == "" {
		activeRevision = recovery.RevisionID
	}
	status := "ok"
	if recovery.Status == "starting" {
		status = "starting"
	} else if recovery.Status == "error" {
		status = "degraded"
	}
	writeData(w, r, map[string]any{
		"status": status, "provider": s.provider.Name(), "simulation": s.provider.Simulation(),
		"recovery_status": recovery.Status, "recovery_reason_code": recovery.ReasonCode,
		"recovery_reason": recovery.Reason, "recovery_commit_phase": recovery.CommitPhase,
		// Bind health to the durable generation that recovery proved. A revision
		// identifier alone is not enough to exclude a stale or foreign artifact.
		"active_revision": activeRevision, "active_candidate_hash": recovery.CandidateHash,
		"active_artifact_manifest_hash": recovery.ArtifactManifestHash,
		"time":                          time.Now().UTC().Format(time.RFC3339),
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
	maxAge := 0 // session cookie for the non-expiring default session
	value := session.ID
	expires := session.ExpiresAt
	if !session.ExpiresAt.IsZero() {
		maxAge = int(time.Until(session.ExpiresAt).Seconds())
	}
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

func countRoutes(cfg *config.Config, typ string) int { return len(filterRoutes(cfg, typ)) }
func filterRoutes(cfg *config.Config, typ string) []config.Route {
	if cfg == nil {
		return nil
	}
	return cfg.RoutesByType(typ)
}

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
	return sanitizeEventDetailsForPrivacy(details, true)
}

func sanitizeEventForPrivacy(event Event, hideAddresses bool) Event {
	event.Details = sanitizeEventDetailsForPrivacy(event.Details, hideAddresses)
	return event
}

func sanitizeEventDetailsForPrivacy(details map[string]any, hideAddresses bool) map[string]any {
	if details == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(details))
	for key, value := range details {
		if sensitiveEventKeyForPrivacy(key, hideAddresses) {
			out[key] = "[redacted]"
			continue
		}
		out[key] = sanitizeEventValueForPrivacy(value, hideAddresses)
	}
	return out
}

func sanitizeEventValue(value any) any {
	return sanitizeEventValueForPrivacy(value, true)
}

func sanitizeEventValueForPrivacy(value any, hideAddresses bool) any {
	switch typed := value.(type) {
	case map[string]any:
		return sanitizeEventDetailsForPrivacy(typed, hideAddresses)
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			out[i] = sanitizeEventValueForPrivacy(typed[i], hideAddresses)
		}
		return out
	default:
		// Providers may put typed maps/slices/structs into Details. Normalize
		// only composite values so []string/map[string]string cannot bypass
		// recursive redaction; scalar values do not incur JSON work.
		rv := reflect.ValueOf(value)
		if !rv.IsValid() {
			return value
		}
		switch rv.Kind() {
		case reflect.Map, reflect.Slice, reflect.Array, reflect.Struct, reflect.Pointer:
			if (rv.Kind() == reflect.Map || rv.Kind() == reflect.Slice || rv.Kind() == reflect.Pointer) && rv.IsNil() {
				return value
			}
			raw, err := json.Marshal(value)
			if err != nil {
				return "[redacted]"
			}
			var normalized any
			if err := json.Unmarshal(raw, &normalized); err != nil {
				return "[redacted]"
			}
			return sanitizeEventValueForPrivacy(normalized, hideAddresses)
		default:
			return value
		}
	}
}

func sensitiveEventKey(key string) bool {
	return sensitiveEventKeyForPrivacy(key, true)
}

func sensitiveEventKeyForPrivacy(key string, hideAddresses bool) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if hideAddresses && addressEventKey(key) {
		return true
	}
	for _, fragment := range []string{"password", "token", "secret", "private_key", "subscription_url", "uuid", "cookie"} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}

func addressEventKey(key string) bool {
	key = strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToLower(strings.TrimSpace(key)))
	if key == "remote" {
		return true
	}
	for _, token := range strings.Split(key, "_") {
		switch token {
		case "ip", "ips", "address", "addresses", "mac", "macs":
			return true
		}
	}
	return false
}
