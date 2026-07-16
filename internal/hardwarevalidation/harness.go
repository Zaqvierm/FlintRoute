package hardwarevalidation

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"router-policy/internal/probe"
)

const (
	maxCommandOutput = 4 << 20
	maxCasesBytes    = 1 << 20
)

var (
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	caseIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)
	ipv4Pattern   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Pattern   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]{0,39}\b`)
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ExecRunner struct {
	Env []string
}

func (r ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(r.Env) > 0 {
		cmd.Env = r.Env
	}
	output, err := cmd.CombinedOutput()
	if len(output) > maxCommandOutput {
		return nil, fmt.Errorf("command output exceeds %d bytes", maxCommandOutput)
	}
	if err != nil {
		return output, fmt.Errorf("%s failed: %w", filepath.Base(name), err)
	}
	return output, nil
}

type Paths struct {
	RouterPolicy    string
	Config          string
	StateDir        string
	RuntimeDir      string
	InitDir         string
	NftBinary       string
	IPBinary        string
	UbusBinary      string
	DFBinary        string
	WatchdogService string
}

func DefaultPaths() Paths {
	return Paths{
		RouterPolicy: "/usr/bin/router-policy", Config: "/etc/router-policy/config/default.json",
		StateDir: "/etc/router-policy/state", RuntimeDir: "/tmp/router-policy", InitDir: "/etc/init.d",
		NftBinary: "/usr/sbin/nft", IPBinary: "/sbin/ip", UbusBinary: "/bin/ubus", DFBinary: "/bin/df",
		WatchdogService: "router-policy-watchdog",
	}
}

type Harness struct {
	Runner Runner
	Paths  Paths
	Now    func() time.Time
}

type BaselineOptions struct {
	RunDir         string
	Commit         string
	BuildSHA256    string
	RecoverySHA256 string
}

type GateCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Reason string `json:"reason,omitempty"`
}

type Metadata struct {
	SchemaVersion  int               `json:"schema_version"`
	CollectedAt    string            `json:"collected_at"`
	Commit         string            `json:"commit"`
	BuildSHA256    string            `json:"build_sha256"`
	RecoverySHA256 string            `json:"recovery_sha256"`
	Architecture   string            `json:"architecture"`
	Board          map[string]string `json:"board"`
}

type Baseline struct {
	CollectedAt      string         `json:"collected_at"`
	AvailableRootKB  int64          `json:"available_root_kb"`
	ControlStatus    map[string]any `json:"control_status"`
	ConfigValidation map[string]any `json:"config_validation"`
	Gate             []GateCheck    `json:"gate"`
	Passed           bool           `json:"passed"`
}

type MatrixCase struct {
	ID                    string `json:"id"`
	Route                 string `json:"route"`
	Domain                string `json:"domain"`
	Service               string `json:"service"`
	ExpectedStatus        string `json:"expected_status"`
	ExpectedRouteType     string `json:"expected_route_type"`
	ExpectedAddressFamily string `json:"expected_address_family,omitempty"`
	ExpectedPathTransport string `json:"expected_path_transport,omitempty"`
	ExpectedPort          int    `json:"expected_port,omitempty"`
	ExpectedQUICPolicy    string `json:"expected_quic_policy,omitempty"`
	RequireTLS            bool   `json:"require_tls,omitempty"`
	RequireContent        bool   `json:"require_content,omitempty"`
	SkipReason            string `json:"skip_reason,omitempty"`
}

type MatrixResult struct {
	ID        string   `json:"id"`
	Status    string   `json:"status"`
	Route     string   `json:"route,omitempty"`
	RouteType string   `json:"route_type,omitempty"`
	Reasons   []string `json:"reasons,omitempty"`
	CheckedAt string   `json:"checked_at"`
}

type MatrixSummary struct {
	Total         int `json:"total"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	NotApplicable int `json:"not_applicable"`
}

func (h Harness) Baseline(ctx context.Context, options BaselineOptions) (Baseline, error) {
	if h.Runner == nil {
		return Baseline{}, errors.New("runner is required")
	}
	if !commitPattern.MatchString(options.Commit) {
		return Baseline{}, errors.New("commit must be a lowercase 40-character SHA")
	}
	if !digestPattern.MatchString(options.BuildSHA256) || !digestPattern.MatchString(options.RecoverySHA256) {
		return Baseline{}, errors.New("build and recovery SHA-256 values are required")
	}
	if err := ensureRunDir(options.RunDir); err != nil {
		return Baseline{}, err
	}

	now := h.now()
	checks := make([]GateCheck, 0, 9)
	checkFile := func(name, path string) {
		info, err := os.Stat(path)
		checks = append(checks, GateCheck{Name: name, Passed: err == nil && !info.IsDir(), Reason: statReason(err, info, false)})
	}
	checkDir := func(name, path string) {
		info, err := os.Stat(path)
		checks = append(checks, GateCheck{Name: name, Passed: err == nil && info.IsDir(), Reason: statReason(err, info, true)})
	}
	checkFile("router_policy_binary", h.Paths.RouterPolicy)
	checkFile("active_config", h.Paths.Config)
	checkFile("state_database", filepath.Join(h.Paths.StateDir, "router-policy.bbolt"))
	checkDir("last_good_artifacts", filepath.Join(h.Paths.StateDir, "last-good"))

	actualBuild, err := hashFile(h.Paths.RouterPolicy)
	checks = append(checks, GateCheck{Name: "build_digest", Passed: err == nil && actualBuild == options.BuildSHA256, Reason: digestReason(err, actualBuild, options.BuildSHA256)})

	transactionState, err := readTransactionState(filepath.Join(h.Paths.RuntimeDir, "active-transaction.env"))
	checks = append(checks, GateCheck{Name: "committed_runtime_binding", Passed: err == nil && transactionState == "committed", Reason: transactionReason(err, transactionState)})

	watchdog := filepath.Join(h.Paths.InitDir, h.Paths.WatchdogService)
	checks = append(checks, commandGate(ctx, h.Runner, "watchdog_running", watchdog, "running"))
	checks = append(checks, commandGate(ctx, h.Runner, "watchdog_enabled", watchdog, "enabled"))

	statusRaw, statusErr := h.Runner.Run(ctx, h.Paths.RouterPolicy, "status")
	status := map[string]any{}
	if statusErr == nil {
		statusErr = json.Unmarshal(statusRaw, &status)
	}
	checks = append(checks, GateCheck{Name: "control_status", Passed: statusErr == nil, Reason: errorReason(statusErr)})

	validationRaw, validationErr := h.Runner.Run(ctx, h.Paths.RouterPolicy, "validate-config")
	validation := map[string]any{}
	if validationErr == nil {
		validationErr = json.Unmarshal(validationRaw, &validation)
	}
	checks = append(checks, GateCheck{Name: "config_validation", Passed: validationErr == nil && validation["valid"] == true, Reason: errorReason(validationErr)})

	rootKB, dfErr := availableKB(ctx, h.Runner, h.Paths.DFBinary)
	checks = append(checks, GateCheck{Name: "recovery_free_space", Passed: dfErr == nil && rootKB >= 262144, Reason: spaceReason(dfErr, rootKB)})

	board := map[string]string{}
	if raw, commandErr := h.Runner.Run(ctx, h.Paths.UbusBinary, "call", "system", "board"); commandErr == nil {
		var value struct {
			Model     string `json:"model"`
			BoardName string `json:"board_name"`
			Kernel    string `json:"kernel"`
			Release   struct {
				Distribution string `json:"distribution"`
				Version      string `json:"version"`
				Description  string `json:"description"`
			} `json:"release"`
		}
		if json.Unmarshal(raw, &value) == nil {
			board = map[string]string{"model": value.Model, "board_name": value.BoardName, "kernel": value.Kernel, "distribution": value.Release.Distribution, "version": value.Release.Version, "description": value.Release.Description}
		}
	}
	architecture := "unknown"
	if raw, commandErr := h.Runner.Run(ctx, "uname", "-m"); commandErr == nil {
		architecture = strings.TrimSpace(string(raw))
	}

	passed := true
	for _, check := range checks {
		if !check.Passed {
			passed = false
		}
	}
	metadata := Metadata{SchemaVersion: 1, CollectedAt: now.Format(time.RFC3339), Commit: options.Commit, BuildSHA256: options.BuildSHA256, RecoverySHA256: options.RecoverySHA256, Architecture: architecture, Board: board}
	baseline := Baseline{CollectedAt: now.Format(time.RFC3339), AvailableRootKB: rootKB, ControlStatus: status, ConfigValidation: validation, Gate: checks, Passed: passed}
	if err := writeJSON(filepath.Join(options.RunDir, "metadata.json"), metadata); err != nil {
		return Baseline{}, err
	}
	if err := writeJSON(filepath.Join(options.RunDir, "baseline.json"), baseline); err != nil {
		return Baseline{}, err
	}
	if err := h.captureSnapshots(ctx, options.RunDir); err != nil {
		return Baseline{}, err
	}
	if !passed {
		return baseline, errors.New("P13 recovery gate failed")
	}
	return baseline, nil
}

func (h Harness) RunMatrix(ctx context.Context, runDir, casesPath string) (MatrixSummary, error) {
	if err := ensureRunDir(runDir); err != nil {
		return MatrixSummary{}, err
	}
	raw, err := readBounded(casesPath, maxCasesBytes)
	if err != nil {
		return MatrixSummary{}, err
	}
	var cases []MatrixCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		return MatrixSummary{}, fmt.Errorf("decode matrix cases: %w", err)
	}
	if len(cases) == 0 || len(cases) > 128 {
		return MatrixSummary{}, errors.New("matrix must contain 1..128 cases")
	}

	resultFile, err := os.OpenFile(filepath.Join(runDir, "matrix.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return MatrixSummary{}, err
	}
	defer resultFile.Close()
	probeFile, err := os.OpenFile(filepath.Join(runDir, "probes.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return MatrixSummary{}, err
	}
	defer probeFile.Close()

	seen := map[string]struct{}{}
	summary := MatrixSummary{Total: len(cases)}
	for _, testCase := range cases {
		if err := validateCase(testCase, seen); err != nil {
			return summary, err
		}
		seen[testCase.ID] = struct{}{}
		result := MatrixResult{ID: testCase.ID, Route: testCase.Route, RouteType: testCase.ExpectedRouteType, CheckedAt: h.now().Format(time.RFC3339)}
		if testCase.SkipReason != "" {
			result.Status = "NOT_APPLICABLE"
			result.Reasons = []string{testCase.SkipReason}
			summary.NotApplicable++
			if err := appendJSON(resultFile, result); err != nil {
				return summary, err
			}
			continue
		}

		probeRaw, runErr := h.Runner.Run(ctx, h.Paths.RouterPolicy, "probe-route", "--no-persist", "--route", testCase.Route, testCase.Domain, testCase.Service)
		if runErr != nil {
			result.Status = "FAIL"
			result.Reasons = []string{"probe command failed"}
			summary.Failed++
			if err := appendJSON(resultFile, result); err != nil {
				return summary, err
			}
			continue
		}
		var routeResult probe.RouteResult
		if err := json.Unmarshal(probeRaw, &routeResult); err != nil {
			return summary, fmt.Errorf("case %s returned invalid probe JSON: %w", testCase.ID, err)
		}
		reasons := evaluateCase(testCase, routeResult)
		if len(reasons) == 0 {
			result.Status = "PASS"
			summary.Passed++
		} else {
			result.Status = "FAIL"
			result.Reasons = reasons
			summary.Failed++
		}
		if err := appendJSON(resultFile, result); err != nil {
			return summary, err
		}
		if err := appendJSON(probeFile, redactProbe(routeResult)); err != nil {
			return summary, err
		}
	}
	if err := writeJSON(filepath.Join(runDir, "matrix-summary.json"), summary); err != nil {
		return summary, err
	}
	if summary.Failed > 0 {
		return summary, fmt.Errorf("hardware matrix has %d failed cases", summary.Failed)
	}
	return summary, nil
}

func Finalize(runDir string) error {
	if err := ensureRunDir(runDir); err != nil {
		return err
	}
	type manifestEntry struct {
		path   string
		digest string
	}
	entries := []manifestEntry{}
	err := filepath.WalkDir(runDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink is forbidden in evidence bundle: %s", path)
		}
		relative, err := filepath.Rel(runDir, path)
		if err != nil {
			return err
		}
		if filepath.ToSlash(relative) == "SHA256SUMS.txt" {
			return nil
		}
		digest, err := hashFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, manifestEntry{path: filepath.ToSlash(relative), digest: digest})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		lines = append(lines, entry.digest+"  "+entry.path)
	}
	return writeAtomic(filepath.Join(runDir, "SHA256SUMS.txt"), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

func ValidateDeviceRunDir(path string) error {
	clean := filepath.Clean(path)
	parent := filepath.Clean("/tmp/flintroute-p13")
	if filepath.Dir(clean) != parent || !caseIDPattern.MatchString(filepath.Base(clean)) {
		return errors.New("device evidence directory must be /tmp/flintroute-p13/<safe-run-id>")
	}
	return nil
}

func (h Harness) captureSnapshots(ctx context.Context, runDir string) error {
	commands := []struct {
		file string
		name string
		args []string
	}{
		{"nft.txt", h.Paths.NftBinary, []string{"list", "table", "inet", "router_policy"}},
		{"ip-rules-v4.txt", h.Paths.IPBinary, []string{"rule", "show"}},
		{"ip-rules-v6.txt", h.Paths.IPBinary, []string{"-6", "rule", "show"}},
		{"ip-routes-v4.txt", h.Paths.IPBinary, []string{"route", "show", "table", "all"}},
		{"ip-routes-v6.txt", h.Paths.IPBinary, []string{"-6", "route", "show", "table", "all"}},
	}
	for _, command := range commands {
		output, err := h.Runner.Run(ctx, command.name, command.args...)
		if err != nil {
			output = []byte("command_unavailable=true\n")
		}
		if err := writeAtomic(filepath.Join(runDir, command.file), redactText(output), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func evaluateCase(testCase MatrixCase, result probe.RouteResult) []string {
	reasons := []string{}
	expectedStatus := testCase.ExpectedStatus
	if expectedStatus == "" {
		expectedStatus = "OK"
	}
	if result.Status != expectedStatus {
		reasons = append(reasons, "unexpected status")
	}
	if result.Simulation {
		reasons = append(reasons, "simulation evidence")
	}
	if !result.PathVerified || result.PathEvidence == nil {
		reasons = append(reasons, "path is not verified")
		return reasons
	}
	proof := result.PathEvidence
	if result.RouteType != testCase.ExpectedRouteType || proof.RouteType != testCase.ExpectedRouteType {
		reasons = append(reasons, "route type mismatch")
	}
	if testCase.ExpectedAddressFamily != "" && proof.AddressFamily != testCase.ExpectedAddressFamily {
		reasons = append(reasons, "address family mismatch")
	}
	if testCase.ExpectedPathTransport != "" && proof.Transport != testCase.ExpectedPathTransport {
		reasons = append(reasons, "path transport mismatch")
	}
	if testCase.ExpectedPort != 0 && proof.ConnectedPort != testCase.ExpectedPort {
		reasons = append(reasons, "connected port mismatch")
	}
	if testCase.ExpectedQUICPolicy != "" && proof.QUICPolicy != testCase.ExpectedQUICPolicy {
		reasons = append(reasons, "QUIC policy mismatch")
	}
	if testCase.RequireTLS && !result.TLSOK {
		reasons = append(reasons, "TLS proof missing")
	}
	if testCase.RequireContent && !result.ContentOK {
		reasons = append(reasons, "content proof missing")
	}
	switch testCase.ExpectedRouteType {
	case "direct":
		if !proof.DirectBypassXray || !proof.DirectBypassZapret {
			reasons = append(reasons, "direct bypass proof missing")
		}
	case "zapret":
		if !proof.ZapretInstalled || !proof.ZapretFlowProcessed || !proof.TCP443Verified {
			reasons = append(reasons, "Zapret flow proof missing")
		}
	case "vless":
		if !proof.SOCKS5Loopback || proof.SOCKS5Endpoint == "" {
			reasons = append(reasons, "VLESS flow proof missing")
		}
	case "drop":
		if !proof.DropIPv4Enforced || !proof.DropIPv6Enforced || !proof.DropDNSEnforced {
			reasons = append(reasons, "DROP family/DNS proof missing")
		}
	case "smart_dns":
		if !proof.DNSResponseSafe || !proof.HostPreserved || !proof.SNIPreserved {
			reasons = append(reasons, "Smart DNS proof missing")
		}
	}
	return reasons
}

func redactProbe(result probe.RouteResult) probe.RouteResult {
	result.DNSResolver = redactValue(result.DNSResolver)
	if result.ResolvedIP != "" {
		result.ResolvedIP = "REDACTED"
	}
	if result.ConnectedIP != "" {
		result.ConnectedIP = "REDACTED"
	}
	if result.LocalIP != "" {
		result.LocalIP = "REDACTED"
	}
	if result.PathEvidence != nil {
		proof := *result.PathEvidence
		proof.ResolvedIP = redactValue(proof.ResolvedIP)
		proof.ConnectedIP = redactValue(proof.ConnectedIP)
		proof.LocalIP = redactValue(proof.LocalIP)
		proof.DNSResolver = redactValue(proof.DNSResolver)
		proof.SOCKS5Endpoint = redactValue(proof.SOCKS5Endpoint)
		result.PathEvidence = &proof
	}
	for index := range result.Checks {
		result.Checks[index].ResolvedIPs = nil
		result.Checks[index].DNSResolver = redactValue(result.Checks[index].DNSResolver)
		result.Checks[index].ConnectedIP = redactValue(result.Checks[index].ConnectedIP)
		result.Checks[index].LocalIP = redactValue(result.Checks[index].LocalIP)
	}
	return result
}

func validateCase(testCase MatrixCase, seen map[string]struct{}) error {
	if !caseIDPattern.MatchString(testCase.ID) {
		return fmt.Errorf("invalid case ID %q", testCase.ID)
	}
	if _, exists := seen[testCase.ID]; exists {
		return fmt.Errorf("duplicate case ID %q", testCase.ID)
	}
	if testCase.SkipReason != "" {
		if len(testCase.SkipReason) > 256 {
			return fmt.Errorf("skip reason is too long for %s", testCase.ID)
		}
		return nil
	}
	for name, value := range map[string]string{"route": testCase.Route, "domain": testCase.Domain, "service": testCase.Service, "expected_route_type": testCase.ExpectedRouteType} {
		if value == "" || !caseIDPattern.MatchString(strings.ToLower(value)) {
			return fmt.Errorf("invalid %s for %s", name, testCase.ID)
		}
	}
	if testCase.ExpectedPort < 0 || testCase.ExpectedPort > 65535 {
		return fmt.Errorf("invalid expected port for %s", testCase.ID)
	}
	return nil
}

func ensureRunDir(path string) error {
	if path == "" {
		return errors.New("run directory is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	clean := filepath.Clean(absolute)
	if clean == string(filepath.Separator) {
		return errors.New("filesystem root cannot be used as run directory")
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return err
	}
	return os.Chmod(clean, 0o700)
}

func (h Harness) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func availableKB(ctx context.Context, runner Runner, binary string) (int64, error) {
	raw, err := runner.Run(ctx, binary, "-Pk", "/")
	if err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	var last []string
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 6 {
			last = fields
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if len(last) < 6 {
		return 0, errors.New("unexpected df output")
	}
	return strconv.ParseInt(last[3], 10, 64)
}

func commandGate(ctx context.Context, runner Runner, name, command string, arg string) GateCheck {
	_, err := runner.Run(ctx, command, arg)
	return GateCheck{Name: name, Passed: err == nil, Reason: errorReason(err)}
}

func readTransactionState(path string) (string, error) {
	raw, err := readBounded(path, 64<<10)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && key == "transaction_state" {
			return strings.TrimSpace(value), nil
		}
	}
	return "", errors.New("transaction_state is missing")
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return raw, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(raw, '\n'), 0o600)
}

func appendJSON(writer io.Writer, value any) error {
	return json.NewEncoder(writer).Encode(value)
}

func writeAtomic(path string, raw []byte, mode os.FileMode) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, raw, mode); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func redactText(raw []byte) []byte {
	text := ipv4Pattern.ReplaceAllString(string(raw), "IP_REDACTED")
	text = ipv6Pattern.ReplaceAllString(text, "IPV6_REDACTED")
	return []byte(text)
}

func redactValue(value string) string {
	if value == "" {
		return ""
	}
	return "REDACTED"
}

func statReason(err error, info os.FileInfo, wantDirectory bool) string {
	if err != nil {
		return "required path is missing"
	}
	if info.IsDir() != wantDirectory {
		return "required path has the wrong type"
	}
	return ""
}

func digestReason(err error, actual, expected string) string {
	if err != nil {
		return "binary digest could not be calculated"
	}
	if actual != expected {
		return "installed binary does not match the requested build digest"
	}
	return ""
}

func transactionReason(err error, state string) string {
	if err != nil {
		return "runtime transaction binding is unavailable"
	}
	if state != "committed" {
		return "runtime transaction is not committed"
	}
	return ""
}

func spaceReason(err error, available int64) string {
	if err != nil {
		return "free space could not be measured"
	}
	if available < 262144 {
		return "less than 256 MiB is available"
	}
	return ""
}

func errorReason(err error) string {
	if err == nil {
		return ""
	}
	return "command failed"
}
