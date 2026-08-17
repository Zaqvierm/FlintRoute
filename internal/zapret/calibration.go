package zapret

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"router-policy/internal/tspu"
)

const calibrationConcurrencyReason = "upstream blockcheck uses shared nft, NFQUEUE and temporary resources"

var errCalibrationUpstreamTimeout = errors.New("upstream Zapret blockcheck timed out")

type CalibrationRequest struct {
	Domain              string `json:"domain"`
	BundleID            string `json:"bundle_id"`
	NetworkFingerprint  string `json:"network_fingerprint"`
	AllowManagedRestart bool   `json:"allow_managed_restart,omitempty"`
}

type CalibrationCandidate struct {
	ProfileID       string   `json:"profile_id"`
	Provider        string   `json:"provider"`
	ProviderVersion string   `json:"provider_version"`
	Transports      []string `json:"transports"`
	Ports           []uint16 `json:"ports"`
	StrategyDigest  string   `json:"strategy_digest"`
	Tests           []string `json:"tests,omitempty"`
	Occurrences     int      `json:"occurrences,omitempty"`
}

type CalibrationStatus struct {
	ID                   string                 `json:"id,omitempty"`
	State                string                 `json:"state"`
	Stage                string                 `json:"stage"`
	Domain               string                 `json:"domain,omitempty"`
	BundleID             string                 `json:"bundle_id,omitempty"`
	NetworkFingerprint   string                 `json:"network_fingerprint,omitempty"`
	Concurrency          int                    `json:"concurrency"`
	ConcurrencyReason    string                 `json:"concurrency_reason"`
	CandidateCount       int                    `json:"candidate_count"`
	ChecksCompleted      int                    `json:"checks_completed,omitempty"`
	ChecksTotal          int                    `json:"checks_total,omitempty"`
	Candidates           []CalibrationCandidate `json:"candidates,omitempty"`
	StartedAt            time.Time              `json:"started_at,omitempty"`
	FinishedAt           time.Time              `json:"finished_at,omitempty"`
	DurationMilliseconds int64                  `json:"duration_ms,omitempty"`
	ErrorCode            string                 `json:"error_code,omitempty"`
	Error                string                 `json:"error,omitempty"`
	ActivationRequired   bool                   `json:"activation_required"`
}

type CalibrationRunner interface {
	Run(context.Context, CalibrationRequest) ([]byte, error)
}

type CalibrationProgressProvider interface {
	Progress() (completed int, total int)
}

// ExecCalibrationRunner is implemented per platform. Production uses the
// Linux implementation; other platforms fail closed and remain testable.
type ExecCalibrationRunner struct {
	Script          string
	Blockcheck      string
	Config          string
	RouterPolicyBin string
	NFQWSBin        string
	ZapretInit      string
	RuntimeDir      string
	CatalogOut      string
}

type CalibrationManager struct {
	Runner  CalibrationRunner
	Timeout time.Duration
	Now     func() time.Time

	mu      sync.Mutex
	current CalibrationStatus
	cancel  context.CancelFunc
}

func NewCalibrationManager(runner CalibrationRunner) *CalibrationManager {
	return &CalibrationManager{Runner: runner, Timeout: 42 * time.Minute}
}

func (m *CalibrationManager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *CalibrationManager) Start(request CalibrationRequest) (CalibrationStatus, error) {
	if m == nil || m.Runner == nil {
		return CalibrationStatus{}, errors.New("Zapret calibration is unavailable")
	}
	normalized, err := tspu.NormalizeDomain(request.Domain)
	if err != nil {
		return CalibrationStatus{}, errors.New("calibration domain is invalid")
	}
	request.Domain = normalized
	if !profileIDPattern.MatchString(request.BundleID) {
		return CalibrationStatus{}, errors.New("calibration bundle ID is invalid")
	}
	if !digestPattern.MatchString(request.NetworkFingerprint) {
		return CalibrationStatus{}, errors.New("verified network fingerprint is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current.State == "running" || m.current.State == "queued" {
		return cloneCalibrationStatus(m.current), errors.New("another Zapret calibration is active")
	}
	now := m.now()
	runID := calibrationRunID(request, now)
	timeout := m.Timeout
	if timeout <= 0 || timeout > 45*time.Minute {
		timeout = 42 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	m.cancel = cancel
	m.current = CalibrationStatus{
		ID: runID, State: "running", Stage: "upstream_blockcheck", Domain: request.Domain,
		BundleID: request.BundleID, NetworkFingerprint: request.NetworkFingerprint,
		Concurrency: 1, ConcurrencyReason: calibrationConcurrencyReason, StartedAt: now,
	}
	go m.run(ctx, request, runID)
	return cloneCalibrationStatus(m.current), nil
}

func (m *CalibrationManager) Status() CalibrationStatus {
	if m == nil {
		return CalibrationStatus{State: "unavailable", Stage: "not_configured", Concurrency: 1, ConcurrencyReason: calibrationConcurrencyReason}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current.State == "" {
		return CalibrationStatus{State: "idle", Stage: "ready", Concurrency: 1, ConcurrencyReason: calibrationConcurrencyReason}
	}
	if (m.current.State == "running" || m.current.State == "queued") && m.Runner != nil {
		if progress, ok := m.Runner.(CalibrationProgressProvider); ok {
			completed, total := progress.Progress()
			if completed > m.current.ChecksCompleted {
				m.current.ChecksCompleted = completed
			}
			if total > 0 {
				m.current.ChecksTotal = total
			}
		}
	}
	return cloneCalibrationStatus(m.current)
}

func (m *CalibrationManager) Cancel() CalibrationStatus {
	if m == nil {
		return CalibrationStatus{State: "unavailable", Stage: "not_configured", Concurrency: 1, ConcurrencyReason: calibrationConcurrencyReason}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil && (m.current.State == "running" || m.current.State == "queued") {
		m.current.Stage = "cancelling"
		m.cancel()
	}
	return cloneCalibrationStatus(m.current)
}

func (m *CalibrationManager) run(ctx context.Context, request CalibrationRequest, runID string) {
	raw, runErr := m.Runner.Run(ctx, request)
	finished := m.now()
	status := CalibrationStatus{
		ID: runID, Domain: request.Domain, BundleID: request.BundleID, NetworkFingerprint: request.NetworkFingerprint,
		Concurrency: 1, ConcurrencyReason: calibrationConcurrencyReason, ActivationRequired: false,
	}
	if runErr != nil {
		status.State, status.Stage, status.ErrorCode, status.Error = "failed", "failed", "zapret_calibration_failed", safeCalibrationError(runErr)
		if errors.Is(runErr, errCalibrationUpstreamTimeout) {
			status.ErrorCode, status.Error = "zapret_calibration_timeout", "upstream blockcheck exceeded the 40 minute bounded runtime"
		} else if errors.Is(ctx.Err(), context.Canceled) {
			status.State, status.Stage, status.ErrorCode, status.Error = "cancelled", "cancelled", "zapret_calibration_cancelled", "calibration was cancelled and cleanup was requested"
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status.ErrorCode, status.Error = "zapret_calibration_timeout", "calibration exceeded the bounded runtime"
		}
	} else {
		candidates, parseErr := parseCalibrationResult(raw)
		if parseErr != nil {
			status.State, status.Stage, status.ErrorCode, status.Error = "failed", "result_validation", "zapret_calibration_result_invalid", parseErr.Error()
		} else {
			status.State, status.Stage = "completed", "candidate_review"
			status.Candidates = candidates
			status.CandidateCount = len(candidates)
			status.ActivationRequired = len(candidates) > 0
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current.ID != runID {
		return
	}
	status.StartedAt = m.current.StartedAt
	status.FinishedAt = finished
	status.DurationMilliseconds = finished.Sub(status.StartedAt).Milliseconds()
	m.current = status
	m.cancel = nil
}

func parseCalibrationResult(raw []byte) ([]CalibrationCandidate, error) {
	var document struct {
		Catalog  CatalogFile `json:"catalog"`
		Evidence []struct {
			ProfileID   string   `json:"profile_id"`
			Tests       []string `json:"tests"`
			Occurrences int      `json:"occurrences"`
		} `json:"evidence"`
	}
	if len(raw) == 0 || len(raw) > 1<<20 || json.Unmarshal(raw, &document) != nil {
		return nil, errors.New("calibration returned malformed bounded JSON")
	}
	if document.Catalog.Version != 1 || len(document.Catalog.Profiles) == 0 || len(document.Catalog.Profiles) > 3 {
		return nil, errors.New("calibration did not return a bounded reviewed catalog")
	}
	evidence := make(map[string]struct {
		Tests       []string
		Occurrences int
	}, len(document.Evidence))
	for _, value := range document.Evidence {
		evidence[value.ProfileID] = struct {
			Tests       []string
			Occurrences int
		}{Tests: append([]string(nil), value.Tests...), Occurrences: value.Occurrences}
	}
	result := make([]CalibrationCandidate, 0, len(document.Catalog.Profiles))
	for _, profile := range document.Catalog.Profiles {
		item := evidence[profile.ID]
		result = append(result, CalibrationCandidate{
			ProfileID: profile.ID, Provider: profile.Provider, ProviderVersion: profile.ProviderVersion,
			Transports: append([]string(nil), profile.Transports...), Ports: append([]uint16(nil), profile.Ports...),
			StrategyDigest: profile.StrategyDigest, Tests: item.Tests, Occurrences: item.Occurrences,
		})
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Occurrences != result[j].Occurrences {
			return result[i].Occurrences > result[j].Occurrences
		}
		return result[i].ProfileID < result[j].ProfileID
	})
	return result, nil
}

func calibrationRunID(request CalibrationRequest, now time.Time) string {
	hash := sha256.Sum256([]byte(request.Domain + "\x00" + request.BundleID + "\x00" + now.UTC().Format(time.RFC3339Nano)))
	return "zapret-" + hex.EncodeToString(hash[:8])
}

func safeCalibrationError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > 240 {
		value = value[:240]
	}
	return value
}

func calibrationCommandError(output []byte) error {
	value := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, string(output))
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return errors.New("Zapret calibration command failed without diagnostic output")
	}
	upstreamTimeout := strings.Contains(value, "upstream blockcheck timed out")
	if len(value) > 240 {
		value = value[len(value)-240:]
	}
	if upstreamTimeout {
		return fmt.Errorf("%w: %s", errCalibrationUpstreamTimeout, value)
	}
	return fmt.Errorf("Zapret calibration command failed: %s", value)
}

func countCompletedCalibrationChecks(raw []byte) int {
	completed := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "UNAVAILABLE") || strings.Contains(line, "!!!!! AVAILABLE !!!!!") {
			completed++
		}
	}
	return completed
}

func cloneCalibrationStatus(status CalibrationStatus) CalibrationStatus {
	status.Candidates = append([]CalibrationCandidate(nil), status.Candidates...)
	for index := range status.Candidates {
		status.Candidates[index].Transports = append([]string(nil), status.Candidates[index].Transports...)
		status.Candidates[index].Ports = append([]uint16(nil), status.Candidates[index].Ports...)
		status.Candidates[index].Tests = append([]string(nil), status.Candidates[index].Tests...)
	}
	return status
}

func (r ExecCalibrationRunner) validatePaths() error {
	for _, path := range []string{r.Script, r.Blockcheck, r.Config, r.RouterPolicyBin, r.NFQWSBin, r.ZapretInit, r.RuntimeDir, r.CatalogOut} {
		if path == "" || !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
			return fmt.Errorf("calibration runner path is invalid")
		}
	}
	return nil
}
