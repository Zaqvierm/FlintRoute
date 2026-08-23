package zapret

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"router-policy/internal/netpolicy"
	"router-policy/internal/tspu"
)

const calibrationConcurrencyReason = "one worker only: curated checks and upstream blockcheck must not share nft/NFQUEUE/process state"

var errCalibrationUpstreamTimeout = errors.New("upstream Zapret blockcheck timed out")
var errCalibrationQuickEvidenceUnavailable = errors.New("quick Zapret calibration requires a curated dataplane evidence runner")

const quickCuratedProfileCount = 4

// CalibrationMode deliberately exposes two different user actions. Quick is
// the bounded/default check; exhaustive is an explicit maintenance operation
// that may run for hours. The runner still owns the actual upstream search
// space: we must not invent a fake "21 strategies" count when the pinned
// blockcheck does not expose one.
type CalibrationMode string

const (
	CalibrationModeQuick      CalibrationMode = "quick"
	CalibrationModeExhaustive CalibrationMode = "exhaustive"
)

func NormalizeCalibrationMode(value string) (CalibrationMode, error) {
	mode := CalibrationMode(strings.ToLower(strings.TrimSpace(value)))
	if mode == "" {
		return CalibrationModeQuick, nil
	}
	switch mode {
	case CalibrationModeQuick, CalibrationModeExhaustive:
		return mode, nil
	default:
		return "", errors.New("calibration mode must be quick or exhaustive")
	}
}

func (mode CalibrationMode) scanLevel() string {
	if mode == CalibrationModeExhaustive {
		return "force"
	}
	return "quick"
}

func (mode CalibrationMode) initialStage() string {
	if mode == CalibrationModeQuick {
		return "curated_dataplane"
	}
	return "upstream_blockcheck"
}

func (mode CalibrationMode) defaultTimeout() time.Duration {
	if mode == CalibrationModeExhaustive {
		return 6 * time.Hour
	}
	return 5 * time.Minute
}

type CalibrationRequest struct {
	Domain              string          `json:"domain"`
	BundleID            string          `json:"bundle_id"`
	NetworkFingerprint  string          `json:"network_fingerprint"`
	ResolvedIPv4        []string        `json:"-"`
	AllowManagedRestart bool            `json:"allow_managed_restart,omitempty"`
	Mode                CalibrationMode `json:"mode,omitempty"`
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

// CalibrationAttempt is deliberately stricter than the legacy blockcheck
// evidence. A process starting or curl returning 200 is not enough to call a
// strategy working: the request must be bound to the tested dataplane and the
// cleanup must be proven as well.
type CalibrationAttempt struct {
	ProfileID                string `json:"profile_id"`
	Target                   string `json:"target"`
	Protocol                 string `json:"protocol"`
	Result                   string `json:"result"`
	PathVerified             bool   `json:"path_verified"`
	CleanupVerified          bool   `json:"cleanup_verified"`
	RouteEvidence            string `json:"route_evidence,omitempty"`
	NFQueuePackets           int64  `json:"nfqueue_packets,omitempty"`
	NFQueueCounterDelta      int64  `json:"nfqueue_counter_delta,omitempty"`
	LatencyMilliseconds      int64  `json:"latency_ms,omitempty"`
	VerificationMilliseconds int64  `json:"verification_duration_ms,omitempty"`
	HTTPStatus               int    `json:"http_status,omitempty"`
	ErrorCode                string `json:"error_code,omitempty"`
	Error                    string `json:"error,omitempty"`
}

type CalibrationStatus struct {
	ID                   string                 `json:"id,omitempty"`
	State                string                 `json:"state"`
	Stage                string                 `json:"stage"`
	Domain               string                 `json:"domain,omitempty"`
	BundleID             string                 `json:"bundle_id,omitempty"`
	NetworkFingerprint   string                 `json:"network_fingerprint,omitempty"`
	Mode                 CalibrationMode        `json:"mode"`
	ScanLevel            string                 `json:"scan_level"`
	Concurrency          int                    `json:"concurrency"`
	ConcurrencyReason    string                 `json:"concurrency_reason"`
	CandidateCount       int                    `json:"candidate_count"`
	ChecksCompleted      int                    `json:"checks_completed,omitempty"`
	ChecksTotal          int                    `json:"checks_total,omitempty"`
	Candidates           []CalibrationCandidate `json:"candidates,omitempty"`
	Attempts             []CalibrationAttempt   `json:"attempts,omitempty"`
	EvidenceLevel        string                 `json:"evidence_level"`
	PathVerified         bool                   `json:"path_verified"`
	RecommendedProfileID string                 `json:"recommended_profile_id,omitempty"`
	LogTail              []string               `json:"log_tail,omitempty"`
	WorkingStrategies    []string               `json:"working_strategies,omitempty"`
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

type CalibrationLiveProvider interface {
	Live() (logTail []string, workingStrategies []string)
}

// ExecCalibrationRunner is implemented per platform. Production uses the
// Linux implementation; other platforms fail closed and remain testable.
type ExecCalibrationRunner struct {
	Script string
	// QuickScript must implement the curated, per-strategy evidence contract.
	// It is intentionally separate from the upstream blockcheck script: using
	// blockcheck with SCANLEVEL=quick is not a substitute for that contract.
	QuickScript     string
	Blockcheck      string
	Config          string
	RouterPolicyBin string
	NFQWSBin        string
	// ManagedQueue is the production queue used when a verified quick result
	// is rendered into the owned dataplane. Quick checks use a separate
	// temporary queue and must never persist that temporary number.
	ManagedQueue int
	ZapretInit   string
	RuntimeDir   string
	CatalogOut   string
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
	// A zero Timeout means use the mode-specific bounded default. Tests and
	// maintenance callers may still set Timeout explicitly for fault injection.
	return &CalibrationManager{Runner: runner}
}

// CatalogPath returns the durable catalog produced by the runner. The path is
// intentionally not exposed in CalibrationStatus because it is an internal
// deployment detail, not part of the user-facing calibration evidence.
func (m *CalibrationManager) CatalogPath() string {
	if m == nil || m.Runner == nil {
		return ""
	}
	provider, ok := m.Runner.(interface{ CatalogPath() string })
	if !ok {
		return ""
	}
	return provider.CatalogPath()
}

func (r ExecCalibrationRunner) CatalogPath() string { return r.CatalogOut }

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
	mode, err := NormalizeCalibrationMode(string(request.Mode))
	if err != nil {
		return CalibrationStatus{}, err
	}
	request.Mode = mode
	if !profileIDPattern.MatchString(request.BundleID) {
		return CalibrationStatus{}, errors.New("calibration bundle ID is invalid")
	}
	if !digestPattern.MatchString(request.NetworkFingerprint) {
		return CalibrationStatus{}, errors.New("verified network fingerprint is required")
	}
	resolvedIPv4, err := normalizeCalibrationIPv4(request.ResolvedIPv4)
	if err != nil {
		return CalibrationStatus{}, err
	}
	request.ResolvedIPv4 = resolvedIPv4
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current.State == "running" || m.current.State == "queued" {
		return cloneCalibrationStatus(m.current), errors.New("another Zapret calibration is active")
	}
	now := m.now()
	runID := calibrationRunID(request, now)
	timeout := m.Timeout
	if timeout <= 0 {
		timeout = request.Mode.defaultTimeout()
	}
	if timeout > 6*time.Hour {
		timeout = 6 * time.Hour
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	m.cancel = cancel
	m.current = CalibrationStatus{
		ID: runID, State: "running", Stage: request.Mode.initialStage(), Domain: request.Domain,
		BundleID: request.BundleID, NetworkFingerprint: request.NetworkFingerprint,
		Mode: request.Mode, ScanLevel: request.Mode.scanLevel(), EvidenceLevel: "none",
		Concurrency: 1, ConcurrencyReason: calibrationConcurrencyReason, StartedAt: now,
	}
	if request.Mode == CalibrationModeQuick {
		m.current.ChecksTotal = quickCuratedProfileCount
	}
	go m.run(ctx, request, runID)
	return cloneCalibrationStatus(m.current), nil
}

func normalizeCalibrationIPv4(values []string) ([]string, error) {
	if len(values) > 8 {
		return nil, errors.New("too many pre-resolved calibration addresses")
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !addr.Is4() || !netpolicy.PublicResolverAddr(addr) {
			return nil, errors.New("pre-resolved calibration address is not a public IPv4 address")
		}
		value = addr.String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
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
		if live, ok := m.Runner.(CalibrationLiveProvider); ok {
			m.current.LogTail, m.current.WorkingStrategies = live.Live()
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
		Mode: request.Mode, ScanLevel: request.Mode.scanLevel(),
		Concurrency: 1, ConcurrencyReason: calibrationConcurrencyReason, ActivationRequired: false,
	}
	if runErr != nil {
		status.State, status.Stage, status.ErrorCode, status.Error = "failed", "failed", "zapret_calibration_failed", safeCalibrationError(runErr)
		if errors.Is(runErr, errCalibrationQuickEvidenceUnavailable) {
			status.Stage, status.ErrorCode, status.Error = "evidence_validation", "zapret_quick_evidence_unavailable", "быстрый тест недоступен: в runtime нет curated runner с доказательством dataplane path"
		}
		if errors.Is(runErr, errCalibrationUpstreamTimeout) {
			status.ErrorCode, status.Error = "zapret_calibration_timeout", "upstream blockcheck exceeded the selected bounded runtime"
		} else if errors.Is(ctx.Err(), context.Canceled) {
			status.State, status.Stage, status.ErrorCode, status.Error = "cancelled", "cancelled", "zapret_calibration_cancelled", "calibration was cancelled and cleanup was requested"
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status.ErrorCode, status.Error = "zapret_calibration_timeout", "calibration exceeded the bounded runtime"
		}
	} else {
		parsed, parseErr := parseCalibrationEvidence(raw, request.Mode, request.Domain)
		if parseErr != nil {
			status.State, status.Stage, status.ErrorCode, status.Error = "failed", "result_validation", "zapret_calibration_result_invalid", parseErr.Error()
			if errors.Is(parseErr, errCalibrationQuickEvidenceUnavailable) {
				status.Stage, status.ErrorCode, status.Error = "evidence_validation", "zapret_quick_evidence_unavailable", "быстрый тест не дал полного доказательства dataplane path"
			}
		} else {
			status.State, status.Stage = "completed", "candidate_review"
			status.Candidates = parsed.Candidates
			status.Attempts = parsed.Attempts
			status.EvidenceLevel = parsed.EvidenceLevel
			status.PathVerified = parsed.PathVerified
			status.CandidateCount = len(parsed.Candidates)
			status.ChecksCompleted = len(parsed.Attempts)
			if request.Mode == CalibrationModeQuick {
				status.ChecksTotal = quickCuratedProfileCount
			}
			status.ActivationRequired = len(parsed.Candidates) > 0
			if len(parsed.Candidates) > 0 {
				status.RecommendedProfileID = parsed.Candidates[0].ProfileID
			}
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

type parsedCalibrationResult struct {
	Candidates    []CalibrationCandidate
	Attempts      []CalibrationAttempt
	EvidenceLevel string
	PathVerified  bool
}

// parseCalibrationResult is kept as a compatibility wrapper for callers that
// only need the legacy exhaustive candidate list. New code must use
// parseCalibrationEvidence so quick results cannot silently lose proof fields.
func parseCalibrationResult(raw []byte) ([]CalibrationCandidate, error) {
	parsed, err := parseCalibrationEvidence(raw, CalibrationModeExhaustive, "")
	if err != nil {
		return nil, err
	}
	return parsed.Candidates, nil
}

func parseCalibrationEvidence(raw []byte, mode CalibrationMode, domain string) (parsedCalibrationResult, error) {
	var document struct {
		Catalog       CatalogFile          `json:"catalog"`
		EvidenceLevel string               `json:"evidence_level"`
		PathVerified  bool                 `json:"path_verified"`
		Attempts      []CalibrationAttempt `json:"attempts"`
		Evidence      []struct {
			ProfileID   string   `json:"profile_id"`
			Tests       []string `json:"tests"`
			Occurrences int      `json:"occurrences"`
		} `json:"evidence"`
	}
	if len(raw) == 0 || len(raw) > 1<<20 || json.Unmarshal(raw, &document) != nil {
		return parsedCalibrationResult{}, errors.New("calibration returned malformed bounded JSON")
	}
	maxCatalogProfiles := 3
	if mode == CalibrationModeQuick {
		// Quick must return the complete bounded curated set so the UI can show
		// every checked strategy. Legacy exhaustive imports remain capped at the
		// small candidate list they historically exposed.
		maxCatalogProfiles = MaxProfiles
	}
	if document.Catalog.Version != 1 || len(document.Catalog.Profiles) == 0 || len(document.Catalog.Profiles) > maxCatalogProfiles {
		return parsedCalibrationResult{}, errors.New("calibration did not return a bounded reviewed catalog")
	}
	if mode == CalibrationModeQuick {
		if len(document.Attempts) == 0 || len(document.Attempts) > MaxProfiles || document.EvidenceLevel != "path_verified" {
			return parsedCalibrationResult{}, errCalibrationQuickEvidenceUnavailable
		}
		normalizedDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		profileIDs := make(map[string]struct{}, len(document.Catalog.Profiles))
		for _, profile := range document.Catalog.Profiles {
			profileIDs[profile.ID] = struct{}{}
		}
		seenAttempts := make(map[string]struct{}, len(document.Attempts))
		passCount := 0
		for index := range document.Attempts {
			attempt := &document.Attempts[index]
			if attempt.ProfileID == "" || attempt.Target == "" || attempt.Protocol == "" || attempt.Target != normalizedDomain || !attempt.CleanupVerified {
				return parsedCalibrationResult{}, errCalibrationQuickEvidenceUnavailable
			}
			if _, ok := profileIDs[attempt.ProfileID]; !ok {
				return parsedCalibrationResult{}, errCalibrationQuickEvidenceUnavailable
			}
			if _, duplicate := seenAttempts[attempt.ProfileID]; duplicate {
				return parsedCalibrationResult{}, errCalibrationQuickEvidenceUnavailable
			}
			seenAttempts[attempt.ProfileID] = struct{}{}
			switch attempt.Result {
			case "PASS":
				if !attempt.PathVerified {
					return parsedCalibrationResult{}, errCalibrationQuickEvidenceUnavailable
				}
				passCount++
			case "FAIL", "TIMEOUT":
				// A bounded strategy failure/timeout is still a valid attempt only
				// when the runner proved that the request traversed the tested
				// path. An infrastructure failure is the explicit exception below.
				if !attempt.PathVerified {
					return parsedCalibrationResult{}, errCalibrationQuickEvidenceUnavailable
				}
			case "INFRA_ERROR":
				if strings.TrimSpace(attempt.ErrorCode) == "" && strings.TrimSpace(attempt.Error) == "" {
					return parsedCalibrationResult{}, errCalibrationQuickEvidenceUnavailable
				}
			default:
				return parsedCalibrationResult{}, errCalibrationQuickEvidenceUnavailable
			}
		}
		if document.PathVerified != (passCount > 0) {
			return parsedCalibrationResult{}, errCalibrationQuickEvidenceUnavailable
		}
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
	quickPass := make(map[string]bool)
	if mode == CalibrationModeQuick {
		for _, attempt := range document.Attempts {
			if attempt.Result == "PASS" && attempt.PathVerified {
				quickPass[attempt.ProfileID] = true
			}
		}
	}
	for _, profile := range document.Catalog.Profiles {
		if mode == CalibrationModeQuick && !quickPass[profile.ID] {
			continue
		}
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
	evidenceLevel := document.EvidenceLevel
	if evidenceLevel == "" {
		// Legacy upstream output is useful as candidate evidence, but it is not
		// path proof. Keep that distinction explicit in the API.
		evidenceLevel = "curl_only"
	}
	return parsedCalibrationResult{Candidates: result, Attempts: append([]CalibrationAttempt(nil), document.Attempts...), EvidenceLevel: evidenceLevel, PathVerified: document.PathVerified}, nil
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

func calibrationLiveSnapshot(raw []byte) ([]string, []string) {
	const maxLines = 80
	lines := make([]string, 0, maxLines)
	working := make([]string, 0, 8)
	seenWorking := map[string]struct{}{}
	previous := ""
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.Map(func(r rune) rune {
			if r == '\t' {
				return ' '
			}
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, rawLine)
		line = strings.Join(strings.Fields(line), " ")
		if line == "" {
			continue
		}
		if len(line) > 240 {
			line = line[:240]
		}
		lines = append(lines, line)
		if len(lines) > maxLines {
			lines = lines[len(lines)-maxLines:]
		}
		if strings.Contains(line, "!!!!! AVAILABLE !!!!!") {
			candidate := previous
			if candidate == "" {
				candidate = fmt.Sprintf("working strategy %d", len(working)+1)
			}
			if _, exists := seenWorking[candidate]; !exists {
				seenWorking[candidate] = struct{}{}
				working = append(working, candidate)
			}
		}
		previous = line
	}
	return append([]string(nil), lines...), append([]string(nil), working...)
}

func cloneCalibrationStatus(status CalibrationStatus) CalibrationStatus {
	status.Candidates = append([]CalibrationCandidate(nil), status.Candidates...)
	status.Attempts = append([]CalibrationAttempt(nil), status.Attempts...)
	status.LogTail = append([]string(nil), status.LogTail...)
	status.WorkingStrategies = append([]string(nil), status.WorkingStrategies...)
	for index := range status.Candidates {
		status.Candidates[index].Transports = append([]string(nil), status.Candidates[index].Transports...)
		status.Candidates[index].Ports = append([]uint16(nil), status.Candidates[index].Ports...)
		status.Candidates[index].Tests = append([]string(nil), status.Candidates[index].Tests...)
	}
	return status
}

func (r ExecCalibrationRunner) validatePaths() error {
	return r.validatePathsFor(CalibrationModeExhaustive)
}

func (r ExecCalibrationRunner) validatePathsFor(mode CalibrationMode) error {
	paths := []string{r.Config, r.RouterPolicyBin, r.NFQWSBin, r.ZapretInit, r.RuntimeDir, r.CatalogOut}
	if mode == CalibrationModeQuick {
		paths = append(paths, r.QuickScript)
	} else {
		paths = append(paths, r.Script, r.Blockcheck)
	}
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
			return fmt.Errorf("calibration runner path is invalid")
		}
	}
	return nil
}
