package zapret

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

const (
	MaxSamplesPerProfile = 256
	MaxRouteCost         = 1000
)

type DecisionKey struct {
	BundleID           string `json:"bundle_id"`
	Transport          string `json:"transport"`
	Port               uint16 `json:"port"`
	IPFamily           string `json:"ip_family"`
	NetworkFingerprint string `json:"network_fingerprint"`
}

type ProbeObservation struct {
	Key                  DecisionKey   `json:"key"`
	ProfileID            string        `json:"profile_id"`
	ObservedAt           time.Time     `json:"observed_at"`
	Success              bool          `json:"success"`
	SafetyGate           bool          `json:"safety_gate"`
	RequiredChecksPassed bool          `json:"required_checks_passed"`
	PathVerified         bool          `json:"path_verified"`
	HardFailure          bool          `json:"hard_failure"`
	Latency              time.Duration `json:"latency"`
}

type RankingPolicy struct {
	WindowDuration         time.Duration
	Retention              time.Duration
	MaxSamplesPerProfile   int
	MinAttempts            int
	MinStableWindows       int
	ProductionMinAttempts  int
	ProductionSuccessRatio float64
	RecentSafetyWindows    int
	WilsonZ                float64
}

type CandidateScore struct {
	Key                  DecisionKey `json:"key"`
	ProfileID            string      `json:"profile_id"`
	Attempts             int         `json:"attempts"`
	Successes            int         `json:"successes"`
	SafetyGate           bool        `json:"safety_gate"`
	RequiredChecksPassed bool        `json:"required_checks_passed"`
	RecentHardFailure    bool        `json:"recent_hard_failure"`
	WilsonLowerBound     float64     `json:"wilson_lower_bound"`
	WilsonUpperBound     float64     `json:"wilson_upper_bound"`
	SuccessRatio         float64     `json:"success_ratio"`
	StableWindows        int         `json:"stable_windows"`
	FailureStreak        int         `json:"failure_streak"`
	MedianLatencyMS      float64     `json:"median_latency_ms"`
	P95LatencyMS         float64     `json:"p95_latency_ms"`
	RouteCost            int         `json:"route_cost"`
	Eligible             bool        `json:"eligible"`
	ProductionReady      bool        `json:"production_ready"`
	LatestObservedAt     time.Time   `json:"latest_observed_at,omitempty"`
}

type Ranker struct {
	mu       sync.Mutex
	bundles  *BundleCatalog
	profiles *Catalog
	policy   RankingPolicy
	samples  map[string]map[string][]ProbeObservation
}

func DefaultRankingPolicy() RankingPolicy {
	return RankingPolicy{
		WindowDuration:         5 * time.Minute,
		Retention:              24 * time.Hour,
		MaxSamplesPerProfile:   128,
		MinAttempts:            5,
		MinStableWindows:       2,
		ProductionMinAttempts:  10,
		ProductionSuccessRatio: 0.95,
		RecentSafetyWindows:    2,
		WilsonZ:                1.96,
	}
}

func NewRanker(bundles *BundleCatalog, profiles *Catalog, policy RankingPolicy) (*Ranker, error) {
	if bundles == nil || profiles == nil {
		return nil, errors.New("bundle and profile catalogs are required")
	}
	if err := validateRankingPolicy(policy); err != nil {
		return nil, err
	}
	return &Ranker{
		bundles: bundles, profiles: profiles, policy: policy,
		samples: make(map[string]map[string][]ProbeObservation),
	}, nil
}

func (r *Ranker) Observe(observation ProbeObservation) (CandidateScore, error) {
	if r == nil {
		return CandidateScore{}, errors.New("Zapret ranker is not initialized")
	}
	normalized, err := r.normalizeObservation(observation)
	if err != nil {
		return CandidateScore{}, err
	}
	key := decisionKeyString(normalized.Key)
	r.mu.Lock()
	defer r.mu.Unlock()
	profiles := r.samples[key]
	if profiles == nil {
		profiles = make(map[string][]ProbeObservation)
		r.samples[key] = profiles
	}
	samples := append(profiles[normalized.ProfileID], normalized)
	cutoff := normalized.ObservedAt.Add(-r.policy.Retention)
	kept := samples[:0]
	for _, sample := range samples {
		if !sample.ObservedAt.Before(cutoff) {
			kept = append(kept, sample)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].ObservedAt.Before(kept[j].ObservedAt) })
	if len(kept) > r.policy.MaxSamplesPerProfile {
		kept = append([]ProbeObservation(nil), kept[len(kept)-r.policy.MaxSamplesPerProfile:]...)
	}
	profiles[normalized.ProfileID] = kept
	return r.scoreLocked(normalized.Key, normalized.ProfileID, 0, normalized.ObservedAt), nil
}

func (r *Ranker) Rank(key DecisionKey, routeCosts map[string]int, now time.Time) ([]CandidateScore, error) {
	if r == nil {
		return nil, errors.New("Zapret ranker is not initialized")
	}
	normalized, bundle, err := r.normalizeDecisionKey(key)
	if err != nil {
		return nil, err
	}
	for profileID, cost := range routeCosts {
		if cost < 0 || cost > MaxRouteCost {
			return nil, fmt.Errorf("route cost for %s is outside 0..%d", profileID, MaxRouteCost)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]CandidateScore, 0, len(bundle.AllowedProfiles))
	for _, profileID := range bundle.AllowedProfiles {
		result = append(result, r.scoreLocked(normalized, profileID, routeCosts[profileID], now.UTC()))
	}
	sort.SliceStable(result, func(i, j int) bool { return BetterCandidate(result[i], result[j]) })
	return result, nil
}

func (r *Ranker) Snapshot(key DecisionKey, profileID string, now time.Time) (CandidateScore, error) {
	if r == nil {
		return CandidateScore{}, errors.New("Zapret ranker is not initialized")
	}
	normalized, bundle, err := r.normalizeDecisionKey(key)
	if err != nil {
		return CandidateScore{}, err
	}
	if !containsString(bundle.AllowedProfiles, profileID) {
		return CandidateScore{}, fmt.Errorf("profile %s is not allowed for bundle %s", profileID, bundle.ID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.scoreLocked(normalized, profileID, 0, now.UTC()), nil
}

func BetterCandidate(left, right CandidateScore) bool {
	if left.Eligible != right.Eligible {
		return left.Eligible
	}
	if left.SafetyGate != right.SafetyGate {
		return left.SafetyGate
	}
	if left.RequiredChecksPassed != right.RequiredChecksPassed {
		return left.RequiredChecksPassed
	}
	if left.WilsonLowerBound != right.WilsonLowerBound {
		return left.WilsonLowerBound > right.WilsonLowerBound
	}
	if left.SuccessRatio != right.SuccessRatio {
		return left.SuccessRatio > right.SuccessRatio
	}
	if left.StableWindows != right.StableWindows {
		return left.StableWindows > right.StableWindows
	}
	if left.FailureStreak != right.FailureStreak {
		return left.FailureStreak < right.FailureStreak
	}
	if latencyOrder(left.MedianLatencyMS) != latencyOrder(right.MedianLatencyMS) {
		return latencyOrder(left.MedianLatencyMS) < latencyOrder(right.MedianLatencyMS)
	}
	if latencyOrder(left.P95LatencyMS) != latencyOrder(right.P95LatencyMS) {
		return latencyOrder(left.P95LatencyMS) < latencyOrder(right.P95LatencyMS)
	}
	if left.RouteCost != right.RouteCost {
		return left.RouteCost < right.RouteCost
	}
	return left.ProfileID < right.ProfileID
}

func (r *Ranker) normalizeObservation(observation ProbeObservation) (ProbeObservation, error) {
	key, bundle, err := r.normalizeDecisionKey(observation.Key)
	if err != nil {
		return ProbeObservation{}, err
	}
	if observation.ObservedAt.IsZero() {
		return ProbeObservation{}, errors.New("probe observation time is required")
	}
	if observation.Latency < 0 || observation.Latency > 10*time.Minute {
		return ProbeObservation{}, errors.New("probe latency is outside the bounded range")
	}
	if observation.HardFailure && observation.Success {
		return ProbeObservation{}, errors.New("hard failure cannot be successful")
	}
	if observation.Success && (!observation.SafetyGate || !observation.RequiredChecksPassed || !observation.PathVerified) {
		return ProbeObservation{}, errors.New("successful probe requires safety, required checks and path proof")
	}
	if !containsString(bundle.AllowedProfiles, observation.ProfileID) {
		return ProbeObservation{}, fmt.Errorf("profile %s is not allowed for bundle %s", observation.ProfileID, bundle.ID)
	}
	profile, ok := r.profiles.Lookup(observation.ProfileID)
	if !ok || !containsString(profile.Transports, key.Transport) || !containsUint16(profile.Ports, key.Port) || !containsString(profile.IPFamilies, key.IPFamily) {
		return ProbeObservation{}, errors.New("profile does not cover the decision key")
	}
	observation.Key = key
	observation.ObservedAt = observation.ObservedAt.UTC()
	return observation, nil
}

func (r *Ranker) normalizeDecisionKey(key DecisionKey) (DecisionKey, ServiceBundle, error) {
	bundle, ok := r.bundles.Lookup(key.BundleID)
	if !ok {
		return DecisionKey{}, ServiceBundle{}, fmt.Errorf("unknown service bundle %q", key.BundleID)
	}
	if !digestPattern.MatchString(key.NetworkFingerprint) {
		return DecisionKey{}, ServiceBundle{}, errors.New("network fingerprint must be a SHA-256 digest")
	}
	if key.IPFamily != "ipv4" && key.IPFamily != "ipv6" || !containsString(bundle.IPFamilies, key.IPFamily) {
		return DecisionKey{}, ServiceBundle{}, errors.New("decision key IP family is outside bundle scope")
	}
	protocolAllowed := false
	for _, protocol := range bundle.Protocols {
		if protocol.Transport == key.Transport && protocol.Port == key.Port {
			protocolAllowed = true
			break
		}
	}
	if !protocolAllowed {
		return DecisionKey{}, ServiceBundle{}, errors.New("decision key protocol is outside bundle scope")
	}
	return key, bundle, nil
}

func (r *Ranker) scoreLocked(key DecisionKey, profileID string, routeCost int, now time.Time) CandidateScore {
	score := CandidateScore{
		Key: key, ProfileID: profileID, RouteCost: routeCost,
		SafetyGate: false, RequiredChecksPassed: false,
	}
	profiles := r.samples[decisionKeyString(key)]
	if profiles == nil {
		return score
	}
	samples := profiles[profileID]
	cutoff := now.Add(-r.policy.Retention)
	active := make([]ProbeObservation, 0, len(samples))
	for _, sample := range samples {
		if !sample.ObservedAt.After(now) && !sample.ObservedAt.Before(cutoff) {
			active = append(active, sample)
		}
	}
	if len(active) == 0 {
		return score
	}
	score.Attempts = len(active)
	score.LatestObservedAt = active[len(active)-1].ObservedAt
	latencies := make([]float64, 0, len(active))
	for _, sample := range active {
		if sample.Success {
			score.Successes++
			if sample.Latency > 0 {
				latencies = append(latencies, float64(sample.Latency)/float64(time.Millisecond))
			}
		}
	}
	score.SuccessRatio = float64(score.Successes) / float64(score.Attempts)
	score.WilsonLowerBound, score.WilsonUpperBound = wilsonBounds(score.Successes, score.Attempts, r.policy.WilsonZ)
	sort.Float64s(latencies)
	score.MedianLatencyMS = percentile(latencies, 0.5)
	score.P95LatencyMS = percentile(latencies, 0.95)
	for index := len(active) - 1; index >= 0 && !active[index].Success; index-- {
		score.FailureStreak++
	}

	type window struct {
		start   time.Time
		samples []ProbeObservation
	}
	windowsByStart := make(map[time.Time][]ProbeObservation)
	starts := make([]time.Time, 0)
	for _, sample := range active {
		start := sample.ObservedAt.Truncate(r.policy.WindowDuration)
		if _, exists := windowsByStart[start]; !exists {
			starts = append(starts, start)
		}
		windowsByStart[start] = append(windowsByStart[start], sample)
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i].After(starts[j]) })
	windows := make([]window, 0, len(starts))
	for _, start := range starts {
		windows = append(windows, window{start: start, samples: windowsByStart[start]})
	}
	for _, item := range windows {
		stable := true
		for _, sample := range item.samples {
			if !sample.Success {
				stable = false
				break
			}
		}
		if !stable {
			break
		}
		score.StableWindows++
	}
	recent := windows
	if len(recent) > r.policy.RecentSafetyWindows {
		recent = recent[:r.policy.RecentSafetyWindows]
	}
	score.SafetyGate = len(recent) > 0
	score.RequiredChecksPassed = len(recent) > 0
	for _, item := range recent {
		for _, sample := range item.samples {
			if !sample.SafetyGate || sample.HardFailure {
				score.SafetyGate = false
			}
			if sample.HardFailure {
				score.RecentHardFailure = true
			}
			if !sample.RequiredChecksPassed || !sample.PathVerified {
				score.RequiredChecksPassed = false
			}
		}
	}
	score.Eligible = score.SafetyGate && score.RequiredChecksPassed &&
		score.Attempts >= r.policy.MinAttempts && score.StableWindows >= r.policy.MinStableWindows
	score.ProductionReady = score.Eligible && !score.RecentHardFailure &&
		score.Attempts >= r.policy.ProductionMinAttempts && score.SuccessRatio >= r.policy.ProductionSuccessRatio
	return score
}

func validateRankingPolicy(policy RankingPolicy) error {
	if policy.WindowDuration < 30*time.Second || policy.WindowDuration > 24*time.Hour {
		return errors.New("ranking window must be between 30 seconds and 24 hours")
	}
	if policy.Retention < 2*policy.WindowDuration || policy.Retention > 30*24*time.Hour {
		return errors.New("ranking retention is outside the bounded range")
	}
	if policy.MaxSamplesPerProfile < 1 || policy.MaxSamplesPerProfile > MaxSamplesPerProfile {
		return fmt.Errorf("ranking sample limit must be within 1..%d", MaxSamplesPerProfile)
	}
	if policy.MinAttempts < 1 || policy.MinAttempts > policy.MaxSamplesPerProfile ||
		policy.ProductionMinAttempts < policy.MinAttempts || policy.ProductionMinAttempts > policy.MaxSamplesPerProfile {
		return errors.New("ranking attempt thresholds are invalid")
	}
	if policy.MinStableWindows < 1 || policy.MinStableWindows > 32 ||
		policy.RecentSafetyWindows < 1 || policy.RecentSafetyWindows > 8 {
		return errors.New("ranking window thresholds are invalid")
	}
	if policy.ProductionSuccessRatio < 0.5 || policy.ProductionSuccessRatio > 1 || policy.WilsonZ < 0.1 || policy.WilsonZ > 5 {
		return errors.New("ranking statistical thresholds are invalid")
	}
	return nil
}

func wilsonBounds(successes, attempts int, z float64) (float64, float64) {
	if attempts == 0 {
		return 0, 0
	}
	n := float64(attempts)
	p := float64(successes) / n
	z2 := z * z
	center := p + z2/(2*n)
	margin := z * math.Sqrt((p*(1-p)+z2/(4*n))/n)
	denominator := 1 + z2/n
	return math.Max(0, (center-margin)/denominator), math.Min(1, (center+margin)/denominator)
}

func percentile(sorted []float64, fraction float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(math.Ceil(fraction*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func latencyOrder(value float64) float64 {
	if value <= 0 {
		return math.MaxFloat64
	}
	return value
}

func decisionKeyString(key DecisionKey) string {
	return fmt.Sprintf("%s|%s|%d|%s|%s", key.BundleID, key.Transport, key.Port, key.IPFamily, key.NetworkFingerprint)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsUint16(values []uint16, target uint16) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
