package zapret

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"sync"
	"time"
)

type ProbeSchedulePolicy struct {
	ActiveInterval       time.Duration
	BackupInterval       time.Duration
	OtherInterval        time.Duration
	ConfirmationWindow   time.Duration
	ConfirmationAttempts int
	ProbeDeadline        time.Duration
	MaxConcurrent        int
	MaxDailyProbes       int
	JitterFraction       float64
}

type ScheduledProbe struct {
	Token       string      `json:"token"`
	Key         DecisionKey `json:"key"`
	ProfileID   string      `json:"profile_id"`
	Class       string      `json:"class"`
	ScheduledAt time.Time   `json:"scheduled_at"`
	Deadline    time.Time   `json:"deadline"`
}

type confirmationState struct {
	remaining int
	deadline  time.Time
}

type ProbeScheduler struct {
	mu            sync.Mutex
	policy        ProbeSchedulePolicy
	lastCompleted map[string]time.Time
	inFlight      map[string]ScheduledProbe
	confirmations map[string]confirmationState
	budgetDay     time.Time
	budgetUsed    int
	sequence      uint64
}

func DefaultProbeSchedulePolicy() ProbeSchedulePolicy {
	return ProbeSchedulePolicy{
		ActiveInterval: 5 * time.Minute, BackupInterval: 30 * time.Minute, OtherInterval: 6 * time.Hour,
		ConfirmationWindow: 2 * time.Minute, ConfirmationAttempts: 3, ProbeDeadline: 45 * time.Second,
		MaxConcurrent: 1, MaxDailyProbes: 512, JitterFraction: 0.10,
	}
}

func NewProbeScheduler(policy ProbeSchedulePolicy) (*ProbeScheduler, error) {
	if err := validateProbeSchedulePolicy(policy); err != nil {
		return nil, err
	}
	return &ProbeScheduler{
		policy: policy, lastCompleted: make(map[string]time.Time), inFlight: make(map[string]ScheduledProbe),
		confirmations: make(map[string]confirmationState),
	}, nil
}

func (s *ProbeScheduler) RequestConfirmation(key DecisionKey, profileID string, now time.Time) error {
	if s == nil || !profileIDPattern.MatchString(profileID) || now.IsZero() {
		return errors.New("complete degradation confirmation request is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.confirmations[scheduleKey(key, profileID)] = confirmationState{
		remaining: s.policy.ConfirmationAttempts,
		deadline:  now.UTC().Add(s.policy.ConfirmationWindow),
	}
	return nil
}

func (s *ProbeScheduler) Next(key DecisionKey, activeProfile string, ranking []CandidateScore, now time.Time) (ScheduledProbe, bool, error) {
	if s == nil || now.IsZero() {
		return ScheduledProbe{}, false, errors.New("probe scheduler and current time are required")
	}
	if err := validateRankingForKey(key, ranking); err != nil {
		return ScheduledProbe{}, false, err
	}
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetBudgetLocked(now)
	s.purgeExpiredLocked(now)
	if len(s.inFlight) >= s.policy.MaxConcurrent || s.budgetUsed >= s.policy.MaxDailyProbes {
		return ScheduledProbe{}, false, nil
	}

	type dueCandidate struct {
		profileID string
		class     string
		interval  time.Duration
		priority  int
	}
	candidates := make([]dueCandidate, 0, len(ranking)+1)
	seen := make(map[string]bool, len(ranking))
	for _, score := range ranking {
		profileID := score.ProfileID
		seen[profileID] = true
		confirmation := s.confirmations[scheduleKey(key, profileID)]
		if confirmation.remaining > 0 && !now.After(confirmation.deadline) {
			candidates = append(candidates, dueCandidate{profileID: profileID, class: "confirmation", priority: 0})
			continue
		}
		if profileID == activeProfile {
			candidates = append(candidates, dueCandidate{profileID: profileID, class: "active", interval: s.policy.ActiveInterval, priority: 1})
			continue
		}
		class, interval, priority := "other", s.policy.OtherInterval, 3
		if score.Eligible {
			class, interval, priority = "backup", s.policy.BackupInterval, 2
		}
		candidates = append(candidates, dueCandidate{profileID: profileID, class: class, interval: interval, priority: priority})
	}
	if activeProfile != "" && !seen[activeProfile] {
		return ScheduledProbe{}, false, errors.New("active profile is absent from ranking")
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority < candidates[j].priority
		}
		return candidates[i].profileID < candidates[j].profileID
	})
	for _, candidate := range candidates {
		keyProfile := scheduleKey(key, candidate.profileID)
		last := s.lastCompleted[keyProfile]
		if candidate.class != "confirmation" && !last.IsZero() {
			dueAt := last.Add(s.jitteredInterval(keyProfile, candidate.interval))
			if now.Before(dueAt) {
				continue
			}
		}
		s.sequence++
		token := Digest([]byte(fmt.Sprintf("%s|%d|%d", keyProfile, now.UnixNano(), s.sequence)))
		probe := ScheduledProbe{
			Token: token, Key: key, ProfileID: candidate.profileID, Class: candidate.class,
			ScheduledAt: now, Deadline: now.Add(s.policy.ProbeDeadline),
		}
		s.inFlight[token] = probe
		s.budgetUsed++
		if candidate.class == "confirmation" {
			confirmation := s.confirmations[keyProfile]
			confirmation.remaining--
			if confirmation.remaining == 0 {
				delete(s.confirmations, keyProfile)
			} else {
				s.confirmations[keyProfile] = confirmation
			}
		}
		return probe, true, nil
	}
	return ScheduledProbe{}, false, nil
}

func (s *ProbeScheduler) Complete(token string, finishedAt time.Time) error {
	if s == nil || token == "" || finishedAt.IsZero() {
		return errors.New("complete probe lease is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	probe, ok := s.inFlight[token]
	if !ok {
		return errors.New("probe lease is unknown or expired")
	}
	finishedAt = finishedAt.UTC()
	if finishedAt.Before(probe.ScheduledAt) || finishedAt.After(probe.Deadline) {
		delete(s.inFlight, token)
		s.lastCompleted[scheduleKey(probe.Key, probe.ProfileID)] = probe.Deadline
		return errors.New("probe completed outside its lease")
	}
	delete(s.inFlight, token)
	s.lastCompleted[scheduleKey(probe.Key, probe.ProfileID)] = finishedAt
	return nil
}

func (s *ProbeScheduler) Budget(now time.Time) (used, limit, inFlight int) {
	if s == nil {
		return 0, 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now = now.UTC()
	s.resetBudgetLocked(now)
	s.purgeExpiredLocked(now)
	return s.budgetUsed, s.policy.MaxDailyProbes, len(s.inFlight)
}

func (s *ProbeScheduler) purgeExpiredLocked(now time.Time) {
	for token, probe := range s.inFlight {
		if !now.Before(probe.Deadline) {
			delete(s.inFlight, token)
			s.lastCompleted[scheduleKey(probe.Key, probe.ProfileID)] = probe.Deadline
		}
	}
	for key, confirmation := range s.confirmations {
		if now.After(confirmation.deadline) {
			delete(s.confirmations, key)
		}
	}
}

func (s *ProbeScheduler) resetBudgetLocked(now time.Time) {
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if !day.Equal(s.budgetDay) {
		s.budgetDay = day
		s.budgetUsed = 0
	}
}

func (s *ProbeScheduler) jitteredInterval(key string, interval time.Duration) time.Duration {
	if interval <= 0 || s.policy.JitterFraction == 0 {
		return interval
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(key))
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], hash.Sum64())
	unit := float64(binary.LittleEndian.Uint64(raw[:])%20001)/10000 - 1
	factor := 1 + unit*s.policy.JitterFraction
	return time.Duration(float64(interval) * factor)
}

func scheduleKey(key DecisionKey, profileID string) string {
	return decisionKeyString(key) + "|" + profileID
}

func validateProbeSchedulePolicy(policy ProbeSchedulePolicy) error {
	if policy.ActiveInterval < time.Minute || policy.ActiveInterval > time.Hour ||
		policy.BackupInterval < policy.ActiveInterval || policy.BackupInterval > 6*time.Hour ||
		policy.OtherInterval < policy.BackupInterval || policy.OtherInterval > 24*time.Hour {
		return errors.New("probe intervals are outside the bounded range")
	}
	if policy.ConfirmationWindow < 30*time.Second || policy.ConfirmationWindow > 10*time.Minute ||
		policy.ConfirmationAttempts < 1 || policy.ConfirmationAttempts > 5 ||
		policy.ProbeDeadline < 5*time.Second || policy.ProbeDeadline > 5*time.Minute {
		return errors.New("probe confirmation policy is outside the bounded range")
	}
	if policy.MaxConcurrent < 1 || policy.MaxConcurrent > 4 || policy.MaxDailyProbes < 1 || policy.MaxDailyProbes > 4096 ||
		policy.JitterFraction < 0 || policy.JitterFraction > 0.5 {
		return errors.New("probe budget is outside the bounded range")
	}
	return nil
}
