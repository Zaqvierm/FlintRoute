package health

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/probe"
)

type ProbeEngine interface {
	ProbeRoute(context.Context, *config.Config, string, string, config.Service, config.Route) probe.RouteResult
}

type Store interface {
	StoreProbeResult(probe.RouteResult) error
	SaveRouteHealth(probe.RouteHealth) error
}

type Service struct {
	Tracker            *probe.HealthTracker
	Store              Store
	Parallelism        int
	MaxControlServices int
}

type CycleResult struct {
	Status        string              `json:"status"`
	RoutesChecked int                 `json:"routes_checked"`
	ProbeCount    int                 `json:"probe_count"`
	Failures      int                 `json:"failures"`
	SelectedTag   string              `json:"selected_tag,omitempty"`
	Health        []probe.RouteHealth `json:"health"`
	StartedAt     time.Time           `json:"started_at"`
	CompletedAt   time.Time           `json:"completed_at"`
}

type namedService struct {
	name    string
	service config.Service
}

type checkedRoute struct {
	route     config.Route
	probes    []probe.RouteResult
	aggregate probe.RouteResult
}

func (s *Service) RunCycle(ctx context.Context, cfg *config.Config, engine ProbeEngine, now time.Time) (CycleResult, error) {
	cycle := CycleResult{Status: "UNVERIFIED", StartedAt: now.UTC()}
	if cfg == nil || engine == nil || s == nil || s.Tracker == nil || s.Store == nil {
		return cycle, errors.New("complete route health dependencies are required")
	}
	routes := cfg.RoutesByType("vless")
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Priority != routes[j].Priority {
			return routes[i].Priority < routes[j].Priority
		}
		return routes[i].Tag < routes[j].Tag
	})
	if len(routes) == 0 {
		cycle.Status = "NOT_APPLICABLE"
		cycle.CompletedAt = time.Now().UTC()
		return cycle, nil
	}

	parallelism := s.Parallelism
	if parallelism <= 0 {
		parallelism = cfg.Policy.ParallelServerChecks
	}
	if parallelism <= 0 {
		parallelism = 4
	}
	if parallelism > 16 {
		parallelism = 16
	}
	if parallelism > len(routes) {
		parallelism = len(routes)
	}
	controlLimit := s.MaxControlServices
	if controlLimit <= 0 {
		controlLimit = 3
	}
	if controlLimit > 8 {
		controlLimit = 8
	}

	jobs := make(chan config.Route)
	results := make(chan checkedRoute, len(routes))
	var workers sync.WaitGroup
	for i := 0; i < parallelism; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for route := range jobs {
				checked := checkRoute(ctx, cfg, engine, route, controlLimit, now.UTC())
				select {
				case results <- checked:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, route := range routes {
			select {
			case jobs <- route:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	checked := make([]checkedRoute, 0, len(routes))
	for result := range results {
		checked = append(checked, result)
	}
	if err := ctx.Err(); err != nil {
		cycle.CompletedAt = time.Now().UTC()
		return cycle, err
	}
	sort.Slice(checked, func(i, j int) bool {
		if checked[i].route.Priority != checked[j].route.Priority {
			return checked[i].route.Priority < checked[j].route.Priority
		}
		return checked[i].route.Tag < checked[j].route.Tag
	})

	var persistErrors []error
	for _, result := range checked {
		cycle.RoutesChecked++
		cycle.ProbeCount += len(result.probes)
		if result.aggregate.Status != "OK" {
			cycle.Failures++
		}
		for _, checkedProbe := range result.probes {
			if err := s.Store.StoreProbeResult(checkedProbe); err != nil {
				persistErrors = append(persistErrors, fmt.Errorf("store probe result for %s: %w", result.route.Tag, err))
			}
		}
		s.Tracker.Observe(result.aggregate, cfg.Policy, now)
	}
	cycle.Health = s.Tracker.AssignVLESSRoles(routes, cfg.Policy, now)
	for _, routeHealth := range cycle.Health {
		if routeHealth.Role == "selected" {
			cycle.SelectedTag = routeHealth.RouteTag
		}
		if err := s.Store.SaveRouteHealth(routeHealth); err != nil {
			persistErrors = append(persistErrors, fmt.Errorf("store route health for %s: %w", routeHealth.RouteTag, err))
		}
	}
	cycle.Status = "UNVERIFIED"
	if cycle.SelectedTag != "" {
		cycle.Status = "OK"
		if cycle.Failures > 0 {
			cycle.Status = "DEGRADED"
		}
	}
	cycle.CompletedAt = time.Now().UTC()
	return cycle, errors.Join(persistErrors...)
}

func checkRoute(ctx context.Context, cfg *config.Config, engine ProbeEngine, route config.Route, controlLimit int, now time.Time) checkedRoute {
	controls := controlServices(cfg, route, controlLimit)
	result := checkedRoute{route: route, probes: make([]probe.RouteResult, 0, len(controls))}
	for _, control := range controls {
		if ctx.Err() != nil {
			break
		}
		checked := engine.ProbeRoute(ctx, cfg, control.service.Domains[0], control.name, control.service, route)
		result.probes = append(result.probes, checked)
	}
	result.aggregate = aggregate(route, result.probes, len(controls), now)
	return result
}

func controlServices(cfg *config.Config, route config.Route, limit int) []namedService {
	controls := make([]namedService, 0, len(cfg.Services))
	for name, service := range cfg.Services {
		if len(service.Domains) == 0 || len(service.ProbeURLs) == 0 || !config.PathAllowed(service, route, cfg.Policy) {
			continue
		}
		controls = append(controls, namedService{name: name, service: service})
	}
	sort.Slice(controls, func(i, j int) bool {
		left := controlCategoryRank(controls[i].service.Category)
		right := controlCategoryRank(controls[j].service.Category)
		if left != right {
			return left < right
		}
		return controls[i].name < controls[j].name
	})
	if len(controls) > limit {
		controls = controls[:limit]
	}
	return controls
}

func controlCategoryRank(category string) int {
	switch category {
	case "GEO_LOCKED":
		return 0
	case "TSPU_RESTRICTED":
		return 1
	case "DIRECT_PREFERRED":
		return 2
	case "TELEGRAM":
		return 3
	default:
		return 4
	}
}

func aggregate(route config.Route, results []probe.RouteResult, configuredControls int, now time.Time) probe.RouteResult {
	aggregate := probe.RouteResult{
		Service: "route-health", Route: route.Tag, RouteType: route.Type, RoutePriority: route.Priority,
		Status: "UNVERIFIED", ApplicationStatus: "UNVERIFIED", CheckedAt: now.UTC().Format(time.RFC3339),
		FailureStage: "health_quorum", ReasonCode: "health_control_quorum_failed",
	}
	if configuredControls < 2 || len(results) < 2 {
		setReason(&aggregate, "insufficient_health_control_services")
		return aggregate
	}
	quorum := configuredControls/2 + 1
	successes := 0
	latencyTotal := int64(0)
	revisions := map[string]bool{}
	candidateHashes := map[string]bool{}
	manifestHashes := map[string]bool{}
	countries := map[string]bool{}
	ipHashes := map[string]bool{}
	firstFailure := ""
	for _, result := range results {
		if !safeHealthResult(route, result) {
			if firstFailure == "" {
				firstFailure = result.ReasonCode
				if firstFailure == "" && result.Reason != nil {
					firstFailure = *result.Reason
				}
			}
			continue
		}
		successes++
		latencyTotal += result.LatencyMS
		revisions[result.AdapterRevision] = true
		candidateHashes[result.CandidateHash] = true
		manifestHashes[result.ArtifactManifestHash] = true
		countries[strings.ToUpper(result.ExternalCountry)] = true
		if result.ExternalIPHash != "" {
			ipHashes[result.ExternalIPHash] = true
		}
	}
	if successes < quorum {
		if firstFailure != "" {
			setReason(&aggregate, firstFailure)
		}
		return aggregate
	}
	if len(revisions) != 1 || len(candidateHashes) != 1 || len(manifestHashes) != 1 || len(countries) != 1 {
		setReason(&aggregate, "health_evidence_consensus_mismatch")
		return aggregate
	}
	aggregate.Status = "OK"
	aggregate.ApplicationStatus = "OK"
	aggregate.PathVerified = true
	aggregate.ServiceOK = true
	aggregate.EgressConsensus = true
	aggregate.AdapterRevision = onlyKey(revisions)
	aggregate.CandidateHash = onlyKey(candidateHashes)
	aggregate.ArtifactManifestHash = onlyKey(manifestHashes)
	aggregate.ExternalCountry = onlyKey(countries)
	if len(ipHashes) == 1 {
		aggregate.ExternalIPHash = onlyKey(ipHashes)
	}
	aggregate.LatencyMS = latencyTotal / int64(successes)
	aggregate.FailureStage = ""
	aggregate.ReasonCode = "health_control_quorum_verified"
	reason := aggregate.ReasonCode
	aggregate.Reason = &reason
	return aggregate
}

func safeHealthResult(route config.Route, result probe.RouteResult) bool {
	country := strings.ToUpper(result.ExternalCountry)
	return result.Route == route.Tag && result.RouteType == route.Type && result.Status == "OK" && result.ApplicationStatus == "OK" && result.PathVerified && result.ServiceOK && result.EgressConsensus && result.AdapterRevision != "" && result.CandidateHash != "" && result.ArtifactManifestHash != "" && result.ExternalIPHash != "" && country != "" && country != "UNKNOWN" && country != "RU"
}

func onlyKey(values map[string]bool) string {
	for value := range values {
		return value
	}
	return ""
}

func setReason(result *probe.RouteResult, reason string) {
	if reason == "" {
		reason = "health_control_quorum_failed"
	}
	result.ReasonCode = reason
	result.Reason = &reason
}
