package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/probe"
)

const (
	selectedRouteFailureDedupe  = 10 * time.Second
	selectedRouteFailureHold    = 5 * time.Minute
	selectedRouteProbeTimeout   = 5 * time.Second
	classifiedRevalidationEvery = 7 * 24 * time.Hour
)

// routeFailureReport is the narrow ingress used by a dataplane consumer when
// a selected route produces a real transport error.  It is deliberately not a
// generic "probe everything" request.
type routeFailureReport struct {
	Domain string
	Route  string
	Reason string
	SeenAt time.Time
}

type classifiedRevalidationRequest struct {
	Domain string `json:"domain"`
}

func (s *Server) handleClassifiedRevalidation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	release, failure := s.acquireMutationLease()
	if failure != nil {
		writeError(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	defer release()
	var request classifiedRevalidationRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, r, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	request.Domain = strings.TrimSpace(request.Domain)
	if request.Domain == "" || len(request.Domain) > 253 {
		writeError(w, r, http.StatusBadRequest, "domain_invalid", "domain is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := s.RevalidateClassifiedDomain(ctx, request.Domain); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "classification_revalidation_failed", err.Error())
		return
	}
	writeData(w, r, map[string]any{"domain": request.Domain, "status": "completed", "probe_count": 1})
}

// ReportSelectedRouteFailure queues one bounded reactive check.  The method
// is safe for a hot request path: it never probes synchronously and drops
// duplicate reports inside a short window.
func (s *Server) ReportSelectedRouteFailure(ctx context.Context, domain, routeTag, reason string) error {
	if s == nil || s.routeFailureQueue == nil {
		return errors.New("route failure monitor is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	routeTag = strings.TrimSpace(routeTag)
	if domain == "" || routeTag == "" {
		return errors.New("domain and route are required")
	}
	active := s.currentConfig()
	if active == nil {
		return errors.New("active configuration is unavailable")
	}
	serviceID := active.ServiceForDomain(domain)
	service, ok := active.Services[serviceID]
	if !ok || service.SelectedRouteTag != routeTag {
		return fmt.Errorf("route %q is not the selected route for %s", routeTag, domain)
	}
	route, ok := active.RouteByTag(routeTag)
	if !ok || route.Type != "vless" || !route.Enabled() {
		return fmt.Errorf("route %q is not an enabled VLESS route", routeTag)
	}
	now := time.Now().UTC()
	key := domain + "\x00" + routeTag
	s.routeFailureMu.Lock()
	if len(s.routeFailureRecent) > 256 {
		cutoff := now.Add(-selectedRouteFailureDedupe)
		for recentKey, seenAt := range s.routeFailureRecent {
			if seenAt.Before(cutoff) {
				delete(s.routeFailureRecent, recentKey)
			}
		}
	}
	if len(s.routeFailureRecent) >= 256 {
		oldestKey := ""
		var oldest time.Time
		for recentKey, seenAt := range s.routeFailureRecent {
			if oldestKey == "" || seenAt.Before(oldest) {
				oldestKey, oldest = recentKey, seenAt
			}
		}
		if oldestKey != "" {
			delete(s.routeFailureRecent, oldestKey)
		}
	}
	for recentRoute, until := range s.routeFailureCooldown {
		if !until.After(now) {
			delete(s.routeFailureCooldown, recentRoute)
		}
	}
	if last := s.routeFailureRecent[key]; !last.IsZero() && now.Sub(last) < selectedRouteFailureDedupe {
		s.routeFailureMu.Unlock()
		return nil
	}
	s.routeFailureRecent[key] = now
	s.routeFailureMu.Unlock()
	report := routeFailureReport{Domain: domain, Route: routeTag, Reason: strings.TrimSpace(reason), SeenAt: now}
	select {
	case s.routeFailureQueue <- report:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		s.publishEvent(Event{Type: "route.failure", Severity: "warning", Domain: domain, Route: routeTag, ReasonCode: "route_failure_queue_full"})
		return errors.New("route failure queue is full")
	}
}

func (s *Server) startRouteFailureScheduler(ctx context.Context) {
	s.schedulerWG.Add(1)
	go func() {
		defer s.schedulerWG.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case report := <-s.routeFailureQueue:
				s.processRouteFailure(ctx, report)
			}
		}
	}()
}

func (s *Server) processRouteFailure(ctx context.Context, report routeFailureReport) {
	if report.SeenAt.IsZero() {
		report.SeenAt = time.Now().UTC()
	}
	active := s.currentConfig()
	if active == nil {
		return
	}
	serviceID := active.ServiceForDomain(report.Domain)
	service, ok := active.Services[serviceID]
	if !ok || service.SelectedRouteTag != report.Route {
		return
	}
	failedRoute, ok := active.RouteByTag(report.Route)
	if !ok || failedRoute.Type != "vless" || !failedRoute.Enabled() {
		return
	}
	failureReason := report.Reason
	if failureReason == "" {
		failureReason = "selected_route_transport_failure"
	}
	reason := failureReason
	failure := probe.RouteResult{Domain: report.Domain, Service: serviceID, Route: report.Route, RouteType: failedRoute.Type, Status: "FAIL", ApplicationStatus: "FAIL", ReasonCode: reason}
	health := s.healthTracker.Observe(failure, active.Policy, report.SeenAt)
	if health.State != "unhealthy" {
		s.publishEvent(Event{Type: "route.failure", Severity: "warning", Domain: report.Domain, Route: report.Route, ReasonCode: "route_failure_suspected", Details: map[string]any{"consecutive_errors": health.ConsecutiveErrors, "threshold": active.Policy.FailAfterConsecutiveErrors}})
		return
	}
	if s.routeFailureOnCooldown(report.Route, report.SeenAt) {
		return
	}
	s.setRouteFailureCooldown(report.Route, report.SeenAt.Add(selectedRouteFailureHold))
	s.scheduleFailedRouteRecovery(report.Route, report.SeenAt.Add(5*time.Minute), 5*time.Minute)

	confirmed := s.probeRouteOnce(ctx, active, report.Domain, serviceID, service, failedRoute)
	if confirmed.Status == "OK" && confirmed.PathVerified && confirmed.ServiceOK {
		s.healthTracker.Observe(confirmed, active.Policy, time.Now().UTC())
		s.publishEvent(Event{Type: "route.failure", Severity: "info", Domain: report.Domain, Route: report.Route, ReasonCode: "route_failure_not_confirmed", Details: map[string]any{"probe_count": 1}})
		return
	}

	fallback, ok := s.nextKnownGoodVLESS(active, service, report.Route)
	if !ok {
		s.publishEvent(Event{Type: "route.fallback", Severity: "error", Domain: report.Domain, Route: report.Route, ReasonCode: "no_safe_route", Details: map[string]any{"probe_count": 1, "reason": "no healthy standby VLESS route"}})
		return
	}
	fallbackResult := s.probeRouteOnce(ctx, active, report.Domain, serviceID, service, fallback)
	if fallbackResult.Status != "OK" || !fallbackResult.PathVerified || !fallbackResult.ServiceOK {
		s.healthTracker.Observe(fallbackResult, active.Policy, time.Now().UTC())
		s.publishEvent(Event{Type: "route.fallback", Severity: "error", Domain: report.Domain, Route: report.Route, ReasonCode: "no_safe_route", Details: map[string]any{"candidate": fallback.Tag, "probe_count": 2, "reason": fallbackResult.ReasonCode}})
		return
	}
	s.healthTracker.Observe(fallbackResult, active.Policy, time.Now().UTC())
	// Reactive health detection may verify a standby route, but it must not
	// invoke the full ChangeSet/apply pipeline from a background event. That
	// pipeline can rebuild Xray/Zapret, nft topology and the management path.
	// Keep the verified fallback as an explicit review action until a dedicated
	// route-only assignment exists for configured services as well as unknown
	// domains.
	s.publishEvent(Event{Type: "route.fallback", Severity: "warning", Domain: report.Domain, Route: fallback.Tag, ReasonCode: "route_failover_pending_review", Details: map[string]any{"from": report.Route, "to": fallback.Tag, "probe_count": 2, "path_verified": true, "assignment": "not_applied"}})
}

func (s *Server) startFailedRouteRecoveryScheduler(ctx context.Context) {
	s.schedulerWG.Add(1)
	go func() {
		defer s.schedulerWG.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				s.runDueFailedRouteRecovery(ctx, now.UTC())
			}
		}
	}()
}

func (s *Server) scheduleFailedRouteRecovery(routeTag string, next time.Time, backoff time.Duration) {
	s.routeFailureMu.Lock()
	if current := s.routeRecoveryNext[routeTag]; current.IsZero() || next.Before(current) {
		s.routeRecoveryNext[routeTag] = next
	}
	if backoff > 0 {
		s.routeRecoveryBackoff[routeTag] = backoff
	}
	s.routeFailureMu.Unlock()
}

func (s *Server) runDueFailedRouteRecovery(ctx context.Context, now time.Time) {
	if failure := s.mutationFailureNow(); failure != nil {
		s.publishEvent(Event{Type: "route.recovery", Severity: "warning", ReasonCode: "mutation_fenced", Details: map[string]any{"code": failure.Code}})
		return
	}
	cfg := s.currentConfig()
	if cfg == nil || s.healthTracker == nil {
		return
	}
	routes := cfg.RoutesByType("vless")
	sort.Slice(routes, func(i, j int) bool { return routes[i].Tag < routes[j].Tag })
	for _, route := range routes {
		health, ok := s.healthTracker.Get(route.Tag)
		if !ok || (health.State != "unhealthy" && health.State != "recovering") {
			continue
		}
		s.routeFailureMu.Lock()
		next := s.routeRecoveryNext[route.Tag]
		s.routeFailureMu.Unlock()
		if next.IsZero() {
			s.scheduleFailedRouteRecovery(route.Tag, now.Add(5*time.Minute), 5*time.Minute)
			continue
		}
		if now.Before(next) {
			continue
		}
		serviceID, service, ok := recoveryServiceForRoute(cfg, route.Tag)
		if !ok {
			s.scheduleRecoveryBackoff(route.Tag, now, false)
			continue
		}
		result := s.probeRouteOnce(ctx, cfg, service.Domains[0], serviceID, service, route)
		recovered := result.Status == "OK" && result.PathVerified && result.ServiceOK
		s.healthTracker.Observe(result, cfg.Policy, now)
		s.scheduleRecoveryBackoff(route.Tag, now, recovered)
		s.publishEvent(Event{Type: "route.recovery", Severity: map[bool]string{true: "info", false: "warning"}[recovered], Domain: service.Domains[0], Route: route.Tag, ReasonCode: map[bool]string{true: "failed_route_recovered", false: "failed_route_still_unhealthy"}[recovered], Details: map[string]any{"probe_count": 1, "path_verified": result.PathVerified, "status": result.Status}})
		return // one cooled-down route per tick
	}
}

func recoveryServiceForRoute(cfg *config.Config, routeTag string) (string, config.Service, bool) {
	for name, service := range cfg.Services {
		if service.SelectedRouteTag == routeTag && len(service.Domains) > 0 && config.PathAllowed(service, config.Route{Tag: routeTag, Type: "vless", Status: "OK"}, cfg.Policy) {
			return name, service, true
		}
	}
	for name, service := range cfg.Services {
		if len(service.Domains) > 0 && containsPath(service.AllowedPaths, "vless") {
			return name, service, true
		}
	}
	return "", config.Service{}, false
}

func containsPath(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func (s *Server) scheduleRecoveryBackoff(routeTag string, now time.Time, recovered bool) {
	s.routeFailureMu.Lock()
	defer s.routeFailureMu.Unlock()
	if recovered {
		delete(s.routeRecoveryNext, routeTag)
		delete(s.routeRecoveryBackoff, routeTag)
		return
	}
	delay := s.routeRecoveryBackoff[routeTag]
	if delay <= 0 {
		delay = 5 * time.Minute
	} else if delay < 6*time.Hour {
		delay *= 3
		if delay > 6*time.Hour {
			delay = 6 * time.Hour
		}
	}
	s.routeRecoveryBackoff[routeTag] = delay
	s.routeRecoveryNext[routeTag] = now.Add(delay)
}

func (s *Server) routeFailureOnCooldown(routeTag string, now time.Time) bool {
	s.routeFailureMu.Lock()
	defer s.routeFailureMu.Unlock()
	until := s.routeFailureCooldown[routeTag]
	return !until.IsZero() && now.Before(until)
}

func (s *Server) setRouteFailureCooldown(routeTag string, until time.Time) {
	s.routeFailureMu.Lock()
	s.routeFailureCooldown[routeTag] = until
	s.routeFailureMu.Unlock()
}

func (s *Server) probeRouteOnce(ctx context.Context, cfg *config.Config, domain, serviceID string, service config.Service, route config.Route) probe.RouteResult {
	if s.probeBudget != nil {
		select {
		case s.probeBudget <- struct{}{}:
			defer func() { <-s.probeBudget }()
		case <-ctx.Done():
			return probe.RouteResult{Domain: domain, Service: serviceID, Route: route.Tag, RouteType: route.Type, Status: "UNVERIFIED", ReasonCode: "route_failure_probe_cancelled"}
		}
	}
	probeCtx, cancel := context.WithTimeout(ctx, selectedRouteProbeTimeout)
	defer cancel()
	return s.probeEngineFactory(cfg).ProbeRoute(probeCtx, cfg, domain, serviceID, service, route)
}

func (s *Server) nextKnownGoodVLESS(cfg *config.Config, service config.Service, failedTag string) (config.Route, bool) {
	for _, route := range s.healthTracker.OrderVLESS(cfg.RoutesByType("vless")) {
		if route.Tag == failedTag || !route.Enabled() || !config.PathAllowed(service, route, cfg.Policy) {
			continue
		}
		health, ok := s.healthTracker.Get(route.Tag)
		if ok && health.State == "healthy" && health.Role != "quarantined" {
			return route, true
		}
	}
	return config.Route{}, false
}

func (s *Server) startClassifiedRevalidationScheduler(ctx context.Context) {
	s.schedulerWG.Add(1)
	go func() {
		defer s.schedulerWG.Done()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				s.runDueClassifiedRevalidation(ctx, now.UTC())
			}
		}
	}()
}

func (s *Server) runDueClassifiedRevalidation(ctx context.Context, now time.Time) {
	cfg := s.currentConfig()
	if cfg == nil {
		return
	}
	names := make([]string, 0, len(cfg.Services))
	for name, service := range cfg.Services {
		if (service.Category == "TSPU_RESTRICTED" || service.Category == "GEO_LOCKED") && len(service.Domains) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		domain := cfg.Services[name].Domains[0]
		s.revalidationMu.Lock()
		next, exists := s.revalidationNext[name]
		if !exists {
			s.revalidationNext[name] = now.Add(classifiedRevalidationEvery)
			s.revalidationMu.Unlock()
			continue
		}
		s.revalidationMu.Unlock()
		if now.Before(next) {
			continue
		}
		_ = s.RevalidateClassifiedDomain(ctx, domain)
		return // one bounded job per scheduler tick
	}
}

// RevalidateClassifiedDomain performs exactly one Direct check for a known
// TSPU/GEO service.  A successful Direct result creates a suggestion only;
// it never silently removes the user's bypass policy.
func (s *Server) RevalidateClassifiedDomain(ctx context.Context, domain string) error {
	if failure := s.mutationFailureNow(); failure != nil {
		return errors.New(failure.Message)
	}
	cfg := s.currentConfig()
	if cfg == nil {
		return errors.New("active configuration is unavailable")
	}
	serviceID := cfg.ServiceForDomain(domain)
	service, ok := cfg.Services[serviceID]
	if !ok || (service.Category != "TSPU_RESTRICTED" && service.Category != "GEO_LOCKED") {
		return fmt.Errorf("%s is not a TSPU/GEO service", domain)
	}
	var direct config.Route
	found := false
	for _, route := range cfg.Routes {
		if route.Type == "direct" && route.Enabled() && config.PathAllowed(service, route, cfg.Policy) {
			direct, found = route, true
			break
		}
	}
	if !found {
		s.publishEvent(Event{Type: "route.revalidation", Severity: "info", Domain: domain, ServiceID: serviceID, ReasonCode: "classification_revalidation_skipped", Details: map[string]any{"reason": "direct route is not allowed for this service"}})
		return nil
	}
	result := s.probeRouteOnce(ctx, cfg, domain, serviceID, service, direct)
	verified := result.Status == "OK" && result.PathVerified && result.ServiceOK
	details := map[string]any{"category": service.Category, "route": direct.Tag, "path_verified": result.PathVerified, "status": result.Status, "reason": result.ReasonCode, "probe_count": 1}
	if verified {
		details["action"] = "suggest_policy_review"
		s.publishEvent(Event{Type: "route.revalidation", Severity: "warning", Domain: domain, ServiceID: serviceID, Route: direct.Tag, ReasonCode: "direct_path_recovered_suggestion", Details: details})
	} else {
		details["action"] = "keep_existing_bypass"
		s.publishEvent(Event{Type: "route.revalidation", Severity: "info", Domain: domain, ServiceID: serviceID, Route: direct.Tag, ReasonCode: "classification_still_requires_bypass", Details: details})
	}
	s.revalidationMu.Lock()
	s.revalidationNext[serviceID] = time.Now().UTC().Add(classifiedRevalidationEvery)
	s.revalidationMu.Unlock()
	return nil
}
