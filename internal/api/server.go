package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"router-policy/internal/health"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
	"router-policy/internal/security"
	"router-policy/internal/state"
	"router-policy/internal/tspu"
	"router-policy/internal/vpnsub"
	"router-policy/internal/web"
)

type Options struct {
	Auth                 *auth.Store
	Provider             platform.Provider
	State                *state.Store
	ProductionAdapter    adapter.Interface
	SubscriptionPreparer SubscriptionPreparer
	ProbeEngineFactory   func(*config.Config) health.ProbeEngine
	TSPURefresh          TSPURefreshFunc
	Development          bool
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
	cfg                  *config.Config
	auth                 *auth.Store
	provider             platform.Provider
	store                *state.Store
	adapter              adapter.Interface
	subscriptionPreparer SubscriptionPreparer
	probeEngineFactory   func(*config.Config) health.ProbeEngine
	tspuRefresh          TSPURefreshFunc
	tspuDelay            tspuDelayFunc
	healthTracker        *probe.HealthTracker
	development          bool
	broker               *EventBroker
	mux                  *http.ServeMux
	mu                   sync.Mutex
	changes              map[string]ChangeSet
	actionLocks          map[string]*actionLockEntry
	transactionMu        sync.Mutex
	subscriptionMu       sync.Mutex
	timers               map[string]*time.Timer
	activeConfig         *config.Config
	activeRevision       string
	configVersion        int64
	recovery             recoveryStatus
	hideSensitive        bool
	adaptiveZapret       *adaptiveRuntime
	schedulerOnce        sync.Once
	schedulerCancel      context.CancelFunc
	schedulerWG          sync.WaitGroup
	closeOnce            sync.Once
	closeErr             error
}

func NewServerWithOptions(cfg *config.Config, opts Options) (*Server, error) {
	if opts.ProductionAdapter == nil {
		return nil, fmt.Errorf("ProductionAdapter dependency is required")
	}
	authStore := opts.Auth
	var err error
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
	s := &Server{
		cfg:                  cfg,
		auth:                 authStore,
		provider:             provider,
		store:                stateStore,
		adapter:              opts.ProductionAdapter,
		subscriptionPreparer: opts.SubscriptionPreparer,
		probeEngineFactory:   probeEngineFactory,
		tspuRefresh:          tspuRefresh,
		tspuDelay:            randomTSPUDelay,
		healthTracker:        probe.NewHealthTracker(persistedHealth),
		development:          opts.Development,
		broker:               NewEventBroker(512),
		mux:                  http.NewServeMux(),
		changes:              changes,
		actionLocks:          map[string]*actionLockEntry{},
		timers:               map[string]*time.Timer{},
		activeConfig:         activeConfig,
		activeRevision:       activeRevision,
		configVersion:        configVersion,
		hideSensitive:        true,
	}
	s.adaptiveZapret, err = buildAdaptiveRuntime(activeConfig, stateStore)
	if err != nil {
		_ = stateStore.Close()
		return nil, fmt.Errorf("initialize adaptive Zapret: %w", err)
	}
	if initial := s.broker.Recent(0, 1); len(initial) == 1 {
		if err := s.persistEvent(initial[0]); err != nil {
			_ = stateStore.Close()
			return nil, fmt.Errorf("persist initial event: %w", err)
		}
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
		cancelScheduler := s.schedulerCancel
		for id, timer := range s.timers {
			timer.Stop()
			delete(s.timers, id)
		}
		s.mu.Unlock()
		if cancelScheduler != nil {
			cancelScheduler()
		}
		s.schedulerWG.Wait()
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
	})
}

func (s *Server) startTSPUScheduler(ctx context.Context) {
	s.schedulerWG.Add(1)
	go func() {
		defer s.schedulerWG.Done()
		s.runTSPUScheduler(ctx)
	}()
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
	service := health.Service{
		Tracker: s.healthTracker, Store: s.store,
		Parallelism: active.Policy.ParallelServerChecks, MaxControlServices: 3,
	}
	cycle, err := service.RunCycle(ctx, active, engine, time.Now().UTC())
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
	s.mux.HandleFunc("/api/v1/domains", s.requireRole(auth.RoleViewer, s.handleDomains))
	s.mux.HandleFunc("/api/v1/policies", s.requireRole(auth.RoleViewer, s.handlePolicies))
	s.mux.HandleFunc("/api/v1/routes", s.requireRole(auth.RoleViewer, s.handleRoutes))
	s.mux.HandleFunc("/api/v1/route-health", s.requireRole(auth.RoleViewer, s.handleRouteHealth))
	s.mux.HandleFunc("/api/v1/proxies", s.requireRole(auth.RoleViewer, s.handleProxies))
	s.mux.HandleFunc("/api/v1/xray/subscription/prepare", s.requireRole(auth.RoleAdministrator, s.handleXraySubscriptionPrepare))
	s.mux.HandleFunc("/api/v1/smart-dns", s.requireRole(auth.RoleViewer, s.handleSmartDNS))
	s.mux.HandleFunc("/api/v1/zapret", s.requireRole(auth.RoleViewer, s.handleZapret))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/evaluate", s.requireRole(auth.RoleAdministrator, s.handleAdaptiveZapretEvaluate))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/state", s.requireRole(auth.RoleAdministrator, s.handleAdaptiveZapretState))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/pin", s.requireRole(auth.RoleAdministrator, s.handleAdaptiveZapretPin))
	s.mux.HandleFunc("/api/v1/zapret/adaptive/unpin", s.requireRole(auth.RoleAdministrator, s.handleAdaptiveZapretUnpin))
	s.mux.HandleFunc("/api/v1/telegram", s.requireRole(auth.RoleViewer, s.handleTelegram))
	s.mux.HandleFunc("/api/v1/diagnostics", s.requireRole(auth.RoleDiagnostician, s.handleDiagnostics))
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
			id = randomHex(12)
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
			"probe_count": len(svc.ProbeURLs), "require_non_ru_egress": svc.RequireNonRUEgress,
		})
	}
	writeData(w, r, items)
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
	writeData(w, r, filterRoutes(s.currentConfig(), "smart_dns"))
}
func (s *Server) handleZapret(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, map[string]any{"status": "requires-flint2-diagnostics", "route": filterRoutes(s.currentConfig(), "zapret")})
}
func (s *Server) handleTelegram(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, map[string]any{"strategy": "tg-ws-proxy -> vless -> drop", "bot_api": "checked separately", "transparent_mode": "requires-flint2"})
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
			"telegram_configured": strings.TrimSpace(cfg.Notifications.TelegramSecretFile) != "",
			"webhook_configured":  strings.TrimSpace(cfg.Notifications.HTTPSWebhookSecretFile) != "",
			"dedupe_seconds":      cfg.Notifications.DedupeSeconds,
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
		cs, failure = s.applyChangeSet(r.Context(), cs)
	case "confirm":
		cs, failure = s.confirmChangeSet(r.Context(), cs)
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

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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
