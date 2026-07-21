package vpnsub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"router-policy/internal/config"
	"router-policy/internal/evidence"
	"router-policy/internal/probe"
	"router-policy/internal/xraybundle"
)

type CandidateProcess interface {
	Stop(context.Context) error
}

type XrayRunner interface {
	Test(context.Context, string) error
	StartCandidate(context.Context, string) (CandidateProcess, error)
	WaitReady(context.Context, []ServerStatus) error
}

type OutboundChecker interface {
	Check(context.Context, string, string) OutboundCheck
}

type OutboundCheck struct {
	Tag             string `json:"tag"`
	Status          string `json:"status"`
	Reason          string `json:"reason,omitempty"`
	LatencyMS       int64  `json:"latency_ms,omitempty"`
	ExternalIPHash  string `json:"external_ip_hash,omitempty"`
	ExternalCountry string `json:"external_country,omitempty"`
}

type PreparedBundle struct {
	CandidateID       string           `json:"candidate_id"`
	BundleHash        string           `json:"bundle_hash"`
	BundlePath        string           `json:"bundle_path"`
	SubscriptionHash  string           `json:"subscription_hash,omitempty"`
	SubscriptionBytes int              `json:"subscription_bytes,omitempty"`
	SelectedTag       string           `json:"selected_tag,omitempty"`
	Checks            []OutboundCheck  `json:"checks"`
	Servers           []ServerStatus   `json:"servers"`
	Routes            []GeneratedRoute `json:"routes"`
	Ready             bool             `json:"ready"`
	SecretsPrinted    bool             `json:"secrets_printed"`
}

type Manager struct {
	StateDir      string
	Runner        XrayRunner
	Checker       OutboundChecker
	Parallelism   int
	CheckAttempts int
}

func (m *Manager) PrepareBundle(ctx context.Context, subscriptionPath string, basePort int) (PreparedBundle, error) {
	if m == nil || m.StateDir == "" || m.Runner == nil || m.Checker == nil {
		return PreparedBundle{}, errors.New("complete Xray manager dependencies are required")
	}
	randomID, err := secureRandomHex(8)
	if err != nil {
		return PreparedBundle{}, fmt.Errorf("generate subscription candidate ID: %w", err)
	}
	candidateID := "cand_" + randomID
	candidateDir := filepath.Join(m.StateDir, "candidates", candidateID)
	candidatePath := filepath.Join(candidateDir, "xray.json")
	defer os.RemoveAll(candidateDir)
	summary, err := GenerateXrayConfigFile(subscriptionPath, candidatePath, basePort)
	result := PreparedBundle{
		CandidateID: candidateID, BundleHash: summary.SHA256, Servers: summary.Servers,
		SecretsPrinted: false,
	}
	if err != nil {
		return result, err
	}
	if err := m.Runner.Test(ctx, candidatePath); err != nil {
		return result, errors.New("xray candidate test failed")
	}
	process, err := m.Runner.StartCandidate(ctx, candidatePath)
	if err != nil {
		return result, errors.New("xray candidate start failed")
	}
	defer process.Stop(context.Background())
	if err := m.Runner.WaitReady(ctx, summary.Servers); err != nil {
		return result, errors.New("xray candidate readiness failed")
	}

	result.Checks = m.checkSupported(ctx, summary.Servers)
	selected := selectHealthyOutbound(result.Checks)
	if selected == nil {
		return result, errors.New("no verified safe VLESS outbound")
	}
	result.SelectedTag = selected.Tag
	if err := process.Stop(ctx); err != nil {
		return result, errors.New("xray candidate stop failed")
	}
	routes := make([]GeneratedRoute, 0, len(summary.Servers))
	for _, server := range summary.Servers {
		if server.Status != "SUPPORTED" {
			continue
		}
		routes = append(routes, GeneratedRoute{
			Type: "vless", Tag: server.Tag, Priority: 100 + len(routes), SOCKS5: server.SOCKS5,
			DNSMode: "socks_remote", ExternalIPProbe: true,
		})
	}
	bundlePath, err := xraybundle.Store(m.StateDir, candidatePath, summary.SHA256)
	if err != nil {
		return result, err
	}
	bundle, err := xraybundle.Load(m.StateDir, summary.SHA256)
	if err != nil {
		_ = os.Remove(bundlePath)
		return result, err
	}
	boundRoutes := make([]config.Route, 0, len(routes))
	for _, route := range routes {
		boundRoutes = append(boundRoutes, config.Route{Type: route.Type, Tag: route.Tag, Priority: route.Priority, SOCKS5: route.SOCKS5, DNSMode: route.DNSMode, ExternalIPProbe: route.ExternalIPProbe})
	}
	if err := xraybundle.ValidateRoutes(bundle, boundRoutes); err != nil {
		_ = os.Remove(bundlePath)
		return result, err
	}
	result.BundlePath = bundlePath
	result.Routes = routes
	result.Ready = true
	return result, nil
}

func (m *Manager) checkSupported(ctx context.Context, servers []ServerStatus) []OutboundCheck {
	parallelism := m.Parallelism
	if parallelism <= 0 {
		parallelism = 4
	}
	if parallelism > 16 {
		parallelism = 16
	}
	type job struct {
		index  int
		server ServerStatus
	}
	type checked struct {
		index int
		value OutboundCheck
	}
	var jobsList []job
	for _, server := range servers {
		if server.Status == "SUPPORTED" {
			jobsList = append(jobsList, job{index: len(jobsList), server: server})
		}
	}
	jobs := make(chan job)
	results := make(chan checked, len(jobsList))
	var workers sync.WaitGroup
	for i := 0; i < parallelism; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for next := range jobs {
				results <- checked{index: next.index, value: m.checkWithRetry(ctx, next.server.Tag, next.server.SOCKS5)}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, next := range jobsList {
			select {
			case jobs <- next:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()
	ordered := make([]OutboundCheck, len(jobsList))
	for result := range results {
		ordered[result.index] = result.value
	}
	return ordered
}

func (m *Manager) checkWithRetry(ctx context.Context, tag, socks5 string) OutboundCheck {
	attempts := m.CheckAttempts
	if attempts <= 0 {
		attempts = 3
	}
	if attempts > 5 {
		attempts = 5
	}
	var result OutboundCheck
	for attempt := 0; attempt < attempts; attempt++ {
		result = m.Checker.Check(ctx, tag, socks5)
		if result.Status == "OK" {
			return result
		}
		select {
		case <-ctx.Done():
			result.Status = "FAIL"
			result.Reason = "candidate_check_cancelled"
			return result
		case <-time.After(time.Duration(attempt+1) * 250 * time.Millisecond):
		}
	}
	return result
}

func selectHealthyOutbound(checks []OutboundCheck) *OutboundCheck {
	healthy := make([]OutboundCheck, 0, len(checks))
	for _, check := range checks {
		if check.Status == "OK" && check.ExternalIPHash != "" && check.ExternalCountry != "" && check.ExternalCountry != "UNKNOWN" && check.ExternalCountry != "RU" {
			healthy = append(healthy, check)
		}
	}
	if len(healthy) == 0 {
		return nil
	}
	sort.SliceStable(healthy, func(i, j int) bool { return healthy[i].LatencyMS < healthy[j].LatencyMS })
	return &healthy[0]
}

type EngineOutboundChecker struct {
	Config  *config.Config
	Service config.Service
}

func (c EngineOutboundChecker) Check(ctx context.Context, tag, socks5 string) OutboundCheck {
	if c.Config == nil || len(c.Service.ProbeURLs) == 0 || len(c.Service.Domains) == 0 {
		return OutboundCheck{Tag: tag, Status: "UNVERIFIED", Reason: "probe_service_not_configured"}
	}
	route := config.Route{Type: "vless", Tag: tag, SOCKS5: socks5, DNSServer: c.Config.Xray.ProbeDNSResolver, DNSMode: "socks_remote", ExternalIPProbe: true}
	result := probe.NewEngine(candidateSOCKSVerifier{}).ProbeRoute(ctx, c.Config, c.Service.Domains[0], "xray-candidate", c.Service, route)
	check := OutboundCheck{
		Tag: tag, Status: "UNVERIFIED", Reason: result.ReasonCode, LatencyMS: result.LatencyMS,
		ExternalIPHash: result.ExternalIPHash, ExternalCountry: result.ExternalCountry,
	}
	if result.Status != "OK" || result.ApplicationStatus != "OK" || !result.PathVerified || !result.ServiceOK || result.XrayOutboundTag != tag {
		if result.Reason != nil {
			check.Reason = *result.Reason
		}
		return check
	}
	for _, applicationCheck := range result.Checks {
		if applicationCheck.Required && applicationCheck.Transport != "socks5" {
			check.Reason = "required_check_did_not_use_socks5"
			return check
		}
	}
	if result.ExternalIPHash == "" || result.ExternalCountry == "" || result.ExternalCountry == "UNKNOWN" {
		check.Reason = "candidate_egress_unverified"
		return check
	}
	check.Status = "OK"
	check.Reason = "candidate_socks_outbound_verified"
	return check
}

type candidateSOCKSVerifier struct{}

func (candidateSOCKSVerifier) Verify(_ context.Context, request probe.PathProofRequest) (evidence.RouteResult, error) {
	if request.Route.Type != "vless" || request.Route.Tag == "" {
		return evidence.RouteResult{}, errors.New("candidate_socks_route_identity_invalid")
	}
	if request.Observation.Transport != "socks5" {
		return evidence.RouteResult{}, errors.New("candidate_socks_transport_unverified")
	}
	if !request.Observation.HostPreserved {
		return evidence.RouteResult{}, errors.New("candidate_socks_host_not_preserved")
	}
	if !request.Observation.SNIPreserved {
		return evidence.RouteResult{}, errors.New("candidate_socks_sni_not_preserved")
	}
	host, _, err := net.SplitHostPort(request.Route.SOCKS5)
	if err != nil {
		return evidence.RouteResult{}, errors.New("candidate_socks_endpoint_invalid")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return evidence.RouteResult{}, errors.New("candidate_socks_endpoint_not_loopback")
	}
	if request.Observation.ExternalIPHash == "" || request.Observation.ExternalCountry == "" || request.Observation.ExternalCountry == "UNKNOWN" {
		return evidence.RouteResult{}, errors.New("candidate_socks_egress_unverified")
	}
	return evidence.RouteResult{
		Domain: request.Observation.Domain, RouteTag: request.Route.Tag, RouteType: request.Route.Type,
		AdapterRevision: "candidate-uncommitted", DNSResolver: request.Observation.DNSResolver,
		ResolvedIP: firstValue(request.Observation.ResolvedIPs), ConnectedIP: request.Observation.ConnectedIP,
		ConnectedPort: request.Observation.ConnectedPort, LocalIP: request.Observation.LocalIP,
		AddressFamily: request.Observation.AddressFamily, Transport: request.Observation.Transport,
		HostPreserved: request.Observation.HostPreserved, SNIPreserved: request.Observation.SNIPreserved,
		XrayOutboundTag: request.Route.Tag, SOCKS5Endpoint: request.Route.SOCKS5, SOCKS5Loopback: true,
		ProxyFlowProcessed: true, ExternalIPHash: request.Observation.ExternalIPHash,
		ExternalCountry: request.Observation.ExternalCountry, TLSResult: request.Observation.TLSResult,
		HTTPResult: request.Observation.HTTPResult, ContentResult: request.Observation.ContentResult,
		Status: "OK", ReasonCode: "isolated_candidate_socks_outbound_verified",
		EvidenceSource: "isolated-xray-candidate-socks", Simulation: true, CheckedAt: time.Now().UTC(),
	}, nil
}

func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

type ExecXrayRunner struct {
	path string
}

func NewExecXrayRunner() (*ExecXrayRunner, error) {
	path, err := firstXrayExecutable("/usr/bin/xray", "/usr/sbin/xray", "/opt/bin/xray")
	if err != nil {
		return nil, err
	}
	return &ExecXrayRunner{path: path}, nil
}

func (r *ExecXrayRunner) Test(ctx context.Context, configPath string) error {
	if _, err := readSecretFile(configPath, 4<<20); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, r.path, "run", "-test", "-config", configPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return errors.New("xray test command failed")
	}
	return nil
}

func (r *ExecXrayRunner) StartCandidate(ctx context.Context, configPath string) (CandidateProcess, error) {
	if _, err := readSecretFile(configPath, 4<<20); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, r.path, "run", "-config", configPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, errors.New("xray start command failed")
	}
	return &execCandidateProcess{cmd: cmd}, nil
}

func (r *ExecXrayRunner) WaitReady(ctx context.Context, servers []ServerStatus) error {
	deadline := time.Now().Add(8 * time.Second)
	for _, server := range servers {
		if server.Status != "SUPPORTED" {
			continue
		}
		for {
			connection, err := (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext(ctx, "tcp", server.SOCKS5)
			if err == nil {
				_ = connection.Close()
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if time.Now().After(deadline) {
				return errors.New("xray SOCKS listener did not become ready")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	return nil
}

type execCandidateProcess struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	stopped bool
}

func (p *execCandidateProcess) Stop(ctx context.Context) error {
	p.mu.Lock()
	if p.stopped || p.cmd == nil || p.cmd.Process == nil {
		p.mu.Unlock()
		return nil
	}
	p.stopped = true
	process := p.cmd.Process
	p.mu.Unlock()
	_ = process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case <-ctx.Done():
		_ = process.Kill()
		<-done
		return ctx.Err()
	case <-time.After(5 * time.Second):
		_ = process.Kill()
		<-done
		return nil
	case <-done:
		return nil
	}
}

func firstXrayExecutable(paths ...string) (string, error) {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("Xray was not found in fixed paths")
}
