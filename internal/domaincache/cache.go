package domaincache

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"router-policy/internal/probe"
	"router-policy/internal/state"
	"router-policy/internal/tspu"
)

const (
	bucket                   = "domain_decisions"
	domainCheckpointInterval = 15 * time.Minute
)

type Store interface {
	SaveJSON(string, string, any) error
	ListRaw(string) ([][]byte, error)
	Delete(string, string) error
}

type Decision struct {
	Key             string              `json:"key"`
	Scope           string              `json:"scope"`
	Domain          string              `json:"domain"`
	ETLDPlusOne     string              `json:"etld_plus_one"`
	Service         string              `json:"service"`
	Category        string              `json:"category"`
	TSPUStatus      string              `json:"tspu_status,omitempty"`
	SelectedRoute   string              `json:"selected_route,omitempty"`
	SelectedType    string              `json:"selected_type,omitempty"`
	Status          string              `json:"status"`
	Reason          string              `json:"reason,omitempty"`
	AdapterRevision string              `json:"adapter_revision"`
	Confidence      float64             `json:"confidence"`
	Results         []probe.RouteResult `json:"results"`
	CheckedAt       time.Time           `json:"checked_at"`
	ExpiresAt       time.Time           `json:"expires_at"`
	LastUsedAt      time.Time           `json:"last_used_at"`
}

type Manager struct {
	mu          sync.Mutex
	store       Store
	max         int
	decisions   map[string]Decision
	checkpoints map[string]time.Time
}

func New(store Store, maxEntries int) (*Manager, error) {
	if store == nil {
		return nil, errors.New("domain decision store is required")
	}
	if maxEntries <= 0 {
		maxEntries = 20000
	}
	if maxEntries > 100000 {
		maxEntries = 100000
	}
	manager := &Manager{store: store, max: maxEntries, decisions: map[string]Decision{}, checkpoints: map[string]time.Time{}}
	rawEntries, err := store.ListRaw(bucket)
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return nil, err
	}
	for _, raw := range rawEntries {
		var decision Decision
		if err := json.Unmarshal(raw, &decision); err != nil {
			return nil, errors.New("invalid persisted domain decision")
		}
		// Older builds persisted failed probes as if they were reusable route
		// decisions. A failure is an observation, not a routing decision: keeping
		// it here can suppress a fresh probe until the TTL expires.
		if decision.SelectedRoute == "" {
			if decision.Key != "" {
				if err := store.Delete(bucket, decision.Key); err != nil && !errors.Is(err, state.ErrNotFound) {
					return nil, err
				}
			}
			continue
		}
		if validateDecision(decision) != nil {
			return nil, errors.New("invalid persisted domain decision")
		}
		manager.decisions[decision.Key] = decision
		manager.checkpoints[decision.Key] = decision.CheckedAt
	}
	if err := manager.pruneLocked(time.Now().UTC()); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *Manager) Lookup(domain, activeRevision string, now time.Time) (Decision, bool, error) {
	if m == nil {
		return Decision{}, false, errors.New("domain decision cache is unavailable")
	}
	normalized, err := tspu.NormalizeDomain(domain)
	if err != nil {
		return Decision{}, false, err
	}
	base := tspu.ETLDPlusOne(normalized)
	exact := exactKey(normalized)
	keys := []string{exact}
	if base != "" {
		keys = append(keys, baseKey(base))
	}
	now = now.UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, key := range keys {
		decision, ok := m.decisions[key]
		if !ok {
			continue
		}
		if !now.Before(decision.ExpiresAt) {
			if err := m.store.Delete(bucket, key); err != nil && !errors.Is(err, state.ErrNotFound) {
				return Decision{}, false, err
			}
			delete(m.decisions, key)
			delete(m.checkpoints, key)
			if key == exact {
				return Decision{}, false, nil
			}
			continue
		}
		if activeRevision != "" && decision.AdapterRevision != activeRevision {
			if key == exact {
				return Decision{}, false, nil
			}
			continue
		}
		if decision.LastUsedAt.IsZero() || now.Sub(decision.LastUsedAt) >= time.Hour {
			decision.LastUsedAt = now
			m.decisions[key] = decision
		}
		return cloneDecision(decision), true, nil
	}
	return Decision{}, false, nil
}

func (m *Manager) Save(domain string, decision Decision) (Decision, error) {
	if m == nil {
		return Decision{}, errors.New("domain decision cache is unavailable")
	}
	normalized, err := tspu.NormalizeDomain(domain)
	if err != nil {
		return Decision{}, err
	}
	base := tspu.ETLDPlusOne(normalized)
	if base == "" {
		return Decision{}, errors.New("domain has no eTLD+1")
	}
	decision.Domain = normalized
	decision.ETLDPlusOne = base
	if decision.CheckedAt.IsZero() || decision.ExpiresAt.IsZero() || !decision.CheckedAt.Before(decision.ExpiresAt) || decision.AdapterRevision == "" {
		return Decision{}, errors.New("complete revision-bound decision metadata is required")
	}
	if decision.LastUsedAt.IsZero() {
		decision.LastUsedAt = decision.CheckedAt
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := baseKey(base)
	scope := "etld_plus_one"
	if normalized != base {
		if current, ok := m.decisions[key]; ok && decisionRouteIdentity(current) != decisionRouteIdentity(decision) {
			key = exactKey(normalized)
			scope = "exact"
		}
	}
	decision.Key = key
	decision.Scope = scope
	if err := validateDecision(decision); err != nil {
		return Decision{}, err
	}
	decision = cloneDecision(decision)
	previous, replaced := m.decisions[key]
	m.decisions[key] = decision
	checkpoint := m.checkpoints[key]
	if replaced && persistentDecisionIdentity(previous) == persistentDecisionIdentity(decision) && !checkpoint.IsZero() &&
		!decision.CheckedAt.Before(checkpoint) && decision.CheckedAt.Sub(checkpoint) < domainCheckpointInterval {
		return cloneDecision(decision), nil
	}
	if err := m.store.SaveJSON(bucket, key, decision); err != nil {
		if replaced {
			m.decisions[key] = previous
		} else {
			delete(m.decisions, key)
		}
		return Decision{}, err
	}
	m.checkpoints[key] = decision.CheckedAt
	if err := m.pruneLocked(decision.CheckedAt); err != nil {
		return Decision{}, err
	}
	return cloneDecision(decision), nil
}

func (m *Manager) Snapshot() []Decision {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Decision, 0, len(m.decisions))
	for _, decision := range m.decisions {
		result = append(result, cloneDecision(decision))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result
}

func (m *Manager) Discard(key string) error {
	if m == nil {
		return errors.New("domain decision cache is unavailable")
	}
	if !strings.HasPrefix(key, "exact:") && !strings.HasPrefix(key, "base:") {
		return errors.New("invalid domain decision key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.store.Delete(bucket, key); err != nil && !errors.Is(err, state.ErrNotFound) {
		return err
	}
	delete(m.decisions, key)
	delete(m.checkpoints, key)
	return nil
}

func (m *Manager) pruneLocked(now time.Time) error {
	for key, decision := range m.decisions {
		if now.Before(decision.ExpiresAt) {
			continue
		}
		if err := m.store.Delete(bucket, key); err != nil && !errors.Is(err, state.ErrNotFound) {
			return err
		}
		delete(m.decisions, key)
		delete(m.checkpoints, key)
	}
	if len(m.decisions) <= m.max {
		return nil
	}
	items := make([]Decision, 0, len(m.decisions))
	for _, decision := range m.decisions {
		items = append(items, decision)
	}
	sort.Slice(items, func(i, j int) bool {
		left := items[i].LastUsedAt
		right := items[j].LastUsedAt
		if left.Equal(right) {
			return items[i].CheckedAt.Before(items[j].CheckedAt)
		}
		return left.Before(right)
	})
	remove := len(items) - m.max
	for i := 0; i < remove; i++ {
		if err := m.store.Delete(bucket, items[i].Key); err != nil && !errors.Is(err, state.ErrNotFound) {
			return err
		}
		delete(m.decisions, items[i].Key)
		delete(m.checkpoints, items[i].Key)
	}
	return nil
}

func validateDecision(decision Decision) error {
	if decision.Key == "" || (decision.Scope != "exact" && decision.Scope != "etld_plus_one") || decision.Service == "" || decision.Category == "" || decision.Status == "" || decision.AdapterRevision == "" || decision.Confidence < 0 || decision.Confidence > 1 || decision.CheckedAt.IsZero() || decision.ExpiresAt.IsZero() || !decision.CheckedAt.Before(decision.ExpiresAt) {
		return errors.New("invalid domain decision metadata")
	}
	normalized, err := tspu.NormalizeDomain(decision.Domain)
	if err != nil || normalized != decision.Domain || tspu.ETLDPlusOne(normalized) != decision.ETLDPlusOne {
		return errors.New("invalid domain decision identity")
	}
	expectedKey := baseKey(decision.ETLDPlusOne)
	if decision.Scope == "exact" {
		expectedKey = exactKey(decision.Domain)
	}
	if decision.Key != expectedKey {
		return errors.New("domain decision key mismatch")
	}
	if decision.SelectedRoute == "" && decision.Status == "SELECTED" {
		return errors.New("selected decision lacks a route")
	}
	return nil
}

func decisionRouteIdentity(decision Decision) string {
	return strings.Join([]string{decision.Status, decision.Category, decision.TSPUStatus, decision.SelectedType, decision.SelectedRoute}, "|")
}

func persistentDecisionIdentity(decision Decision) string {
	return strings.Join([]string{decisionRouteIdentity(decision), decision.Service, decision.AdapterRevision}, "|")
}

func exactKey(domain string) string { return "exact:" + domain }
func baseKey(domain string) string  { return "base:" + domain }

func cloneDecision(decision Decision) Decision {
	decision.Results = append([]probe.RouteResult(nil), decision.Results...)
	for i := range decision.Results {
		decision.Results[i].Checks = append([]probe.CheckResult(nil), decision.Results[i].Checks...)
		decision.Results[i].ExternalCountrySources = append([]string(nil), decision.Results[i].ExternalCountrySources...)
		if decision.Results[i].Reason != nil {
			reason := *decision.Results[i].Reason
			decision.Results[i].Reason = &reason
		}
	}
	return decision
}

func KeyForDomain(domain, scope string) (string, error) {
	normalized, err := tspu.NormalizeDomain(domain)
	if err != nil {
		return "", err
	}
	switch scope {
	case "exact":
		return exactKey(normalized), nil
	case "etld_plus_one":
		return baseKey(tspu.ETLDPlusOne(normalized)), nil
	default:
		return "", fmt.Errorf("unsupported decision scope: %s", scope)
	}
}
