package probe

import (
	"sort"
	"sync"
	"time"

	"router-policy/internal/config"
)

type RouteHealth struct {
	RouteTag             string    `json:"route_tag"`
	RouteType            string    `json:"route_type"`
	State                string    `json:"state"`
	Role                 string    `json:"role"`
	Score                int       `json:"score"`
	ConsecutiveErrors    int       `json:"consecutive_errors"`
	ConsecutiveSuccesses int       `json:"consecutive_successes"`
	Checks               int64     `json:"checks"`
	AvailabilityEWMA     float64   `json:"availability_ewma"`
	EWMALatencyMS        float64   `json:"ewma_latency_ms"`
	LastSuccessAt        time.Time `json:"last_success_at,omitempty"`
	LastFailureAt        time.Time `json:"last_failure_at,omitempty"`
	LastCheckedAt        time.Time `json:"last_checked_at,omitempty"`
	HoldUntil            time.Time `json:"hold_until,omitempty"`
	RoleHoldUntil        time.Time `json:"role_hold_until,omitempty"`
	LastStatus           string    `json:"last_status,omitempty"`
	LastReason           string    `json:"last_reason,omitempty"`
	AdapterRevision      string    `json:"adapter_revision,omitempty"`
	CandidateHash        string    `json:"candidate_hash,omitempty"`
	ArtifactManifestHash string    `json:"artifact_manifest_hash,omitempty"`
	ExternalIPHash       string    `json:"external_ip_hash,omitempty"`
	ExternalCountry      string    `json:"external_country,omitempty"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type HealthTracker struct {
	mu     sync.RWMutex
	routes map[string]RouteHealth
}

func NewHealthTracker(initial []RouteHealth) *HealthTracker {
	tracker := &HealthTracker{routes: make(map[string]RouteHealth, len(initial))}
	for _, health := range initial {
		if health.RouteTag != "" {
			tracker.routes[health.RouteTag] = health
		}
	}
	return tracker
}

func (t *HealthTracker) Observe(result RouteResult, policy config.Policy, now time.Time) RouteHealth {
	if t == nil || result.Route == "" {
		return RouteHealth{}
	}
	now = now.UTC()
	failAfter := policy.FailAfterConsecutiveErrors
	if failAfter <= 0 {
		failAfter = 3
	}
	recoverAfter := policy.RecoverAfterConsecutiveSuccess
	if recoverAfter <= 0 {
		recoverAfter = 3
	}
	hold := time.Duration(policy.RouteHoldSeconds) * time.Second
	if hold < 0 {
		hold = 0
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	health := t.routes[result.Route]
	if health.RouteTag == "" {
		health = RouteHealth{RouteTag: result.Route, RouteType: result.RouteType, State: "unknown", Role: "quarantined", Score: 50}
	}
	success := result.Status == "OK" && result.PathVerified && result.ServiceOK
	health.Checks++
	health.LastCheckedAt = now
	health.LastStatus = result.Status
	if health.Checks == 1 {
		if success {
			health.AvailabilityEWMA = 1
		}
	} else if success {
		health.AvailabilityEWMA = health.AvailabilityEWMA*0.8 + 0.2
	} else {
		health.AvailabilityEWMA *= 0.8
	}
	if result.AdapterRevision != "" {
		health.AdapterRevision = result.AdapterRevision
	}
	if result.CandidateHash != "" {
		health.CandidateHash = result.CandidateHash
	}
	if result.ArtifactManifestHash != "" {
		health.ArtifactManifestHash = result.ArtifactManifestHash
	}
	if result.ExternalIPHash != "" {
		health.ExternalIPHash = result.ExternalIPHash
	}
	if result.ExternalCountry != "" {
		health.ExternalCountry = result.ExternalCountry
	}
	if success {
		health.ConsecutiveSuccesses++
		health.ConsecutiveErrors = 0
		health.LastSuccessAt = now
		health.LastReason = ""
		health.Score = minInt(100, health.Score+10)
		if result.LatencyMS > 0 {
			if health.EWMALatencyMS == 0 {
				health.EWMALatencyMS = float64(result.LatencyMS)
			} else {
				health.EWMALatencyMS = health.EWMALatencyMS*0.7 + float64(result.LatencyMS)*0.3
			}
		}
		if (health.State == "unhealthy" || health.State == "recovering") && (now.Before(health.HoldUntil) || health.ConsecutiveSuccesses < recoverAfter) {
			health.State = "recovering"
		} else {
			health.State = "healthy"
		}
	} else {
		health.ConsecutiveErrors++
		health.ConsecutiveSuccesses = 0
		health.LastFailureAt = now
		health.LastReason = result.ReasonCode
		if health.LastReason == "" && result.Reason != nil {
			health.LastReason = *result.Reason
		}
		health.Score = maxInt(0, health.Score-20)
		if result.Status == "NOT_CONFIGURED" {
			health.State = "not_configured"
		} else if health.ConsecutiveErrors >= failAfter {
			health.State = "unhealthy"
			health.HoldUntil = now.Add(hold)
		}
	}
	health.UpdatedAt = now
	t.routes[result.Route] = health
	return health
}

func (t *HealthTracker) AssignVLESSRoles(routes []config.Route, policy config.Policy, now time.Time) []RouteHealth {
	if t == nil {
		return nil
	}
	now = now.UTC()
	hold := time.Duration(policy.RouteHoldSeconds) * time.Second
	if hold < 0 {
		hold = 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	type candidate struct {
		route  config.Route
		health RouteHealth
	}
	candidates := make([]candidate, 0, len(routes))
	currentSelected := ""
	for _, route := range routes {
		if route.Type != "vless" || !route.Enabled() {
			continue
		}
		health := t.routes[route.Tag]
		if health.RouteTag == "" {
			health = RouteHealth{RouteTag: route.Tag, RouteType: route.Type, State: "unknown", Role: "quarantined", Score: 50, UpdatedAt: now}
		}
		if health.Role == "selected" && health.State == "healthy" && now.Before(health.RoleHoldUntil) {
			currentSelected = route.Tag
		}
		candidates = append(candidates, candidate{route: route, health: health})
	}
	if currentSelected == "" {
		sort.SliceStable(candidates, func(i, j int) bool {
			left, right := candidates[i], candidates[j]
			leftHealthy := left.health.State == "healthy"
			rightHealthy := right.health.State == "healthy"
			if leftHealthy != rightHealthy {
				return leftHealthy
			}
			if left.health.Score != right.health.Score {
				return left.health.Score > right.health.Score
			}
			leftLatency := left.health.EWMALatencyMS
			rightLatency := right.health.EWMALatencyMS
			if leftLatency == 0 {
				leftLatency = 1e12
			}
			if rightLatency == 0 {
				rightLatency = 1e12
			}
			if leftLatency != rightLatency {
				return leftLatency < rightLatency
			}
			if left.route.Priority != right.route.Priority {
				return left.route.Priority < right.route.Priority
			}
			return left.route.Tag < right.route.Tag
		})
		if len(candidates) > 0 && candidates[0].health.State == "healthy" {
			currentSelected = candidates[0].route.Tag
		}
	}

	result := make([]RouteHealth, 0, len(candidates))
	for _, item := range candidates {
		health := item.health
		role := "quarantined"
		if health.State == "healthy" {
			role = "standby"
			if item.route.Tag == currentSelected {
				role = "selected"
			}
		}
		if health.Role != role {
			health.Role = role
			health.UpdatedAt = now
			if role == "selected" {
				health.RoleHoldUntil = now.Add(hold)
			} else {
				health.RoleHoldUntil = time.Time{}
			}
		}
		t.routes[item.route.Tag] = health
		result = append(result, health)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RouteTag < result[j].RouteTag })
	return result
}

func (t *HealthTracker) Snapshot() []RouteHealth {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]RouteHealth, 0, len(t.routes))
	for _, health := range t.routes {
		result = append(result, health)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RouteTag < result[j].RouteTag })
	return result
}

func (t *HealthTracker) OrderSmartDNS(routes []config.Route) []config.Route {
	ordered := append([]config.Route(nil), routes...)
	if t == nil {
		return ordered
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	sort.SliceStable(ordered, func(i, j int) bool {
		left := t.routes[ordered[i].Tag]
		right := t.routes[ordered[j].Tag]
		leftRank := healthRank(left.State)
		rightRank := healthRank(right.State)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		return ordered[i].Tag < ordered[j].Tag
	})
	return ordered
}

func (t *HealthTracker) OrderVLESS(routes []config.Route) []config.Route {
	ordered := append([]config.Route(nil), routes...)
	if t == nil {
		return ordered
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	sort.SliceStable(ordered, func(i, j int) bool {
		left := t.routes[ordered[i].Tag]
		right := t.routes[ordered[j].Tag]
		leftRank := vlessRoleRank(left)
		rightRank := vlessRoleRank(right)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		leftLatency, rightLatency := left.EWMALatencyMS, right.EWMALatencyMS
		if leftLatency == 0 {
			leftLatency = 1e12
		}
		if rightLatency == 0 {
			rightLatency = 1e12
		}
		if leftLatency != rightLatency {
			return leftLatency < rightLatency
		}
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		return ordered[i].Tag < ordered[j].Tag
	})
	return ordered
}

func vlessRoleRank(health RouteHealth) int {
	if health.State == "healthy" && health.Role == "selected" {
		return 0
	}
	if health.State == "healthy" && health.Role == "standby" {
		return 1
	}
	return healthRank(health.State) + 2
}

func healthRank(state string) int {
	switch state {
	case "healthy":
		return 0
	case "unknown", "":
		return 1
	case "recovering":
		return 2
	case "unhealthy":
		return 3
	case "not_configured":
		return 4
	default:
		return 3
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
