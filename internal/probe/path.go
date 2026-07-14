package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"router-policy/internal/artifact"
	"router-policy/internal/config"
	"router-policy/internal/evidence"
)

const defaultProofMaxAge = 5 * time.Minute

var ErrPathEvidenceUnavailable = errors.New("route path evidence unavailable")

type PathStatusError struct {
	Status string
	Code   string
	Err    error
}

func (e *PathStatusError) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Err.Error()
	}
	return e.Code
}

func (e *PathStatusError) Unwrap() error { return e.Err }

func pathStatusError(status, code string, err error) error {
	return &PathStatusError{Status: status, Code: code, Err: err}
}

type PathObservation struct {
	Domain          string
	RouteTag        string
	RouteType       string
	DNSResolver     string
	DNSProtocol     string
	ResolvedIPs     []string
	ConnectedIP     string
	ConnectedPort   int
	LocalIP         string
	AddressFamily   string
	Transport       string
	SocketMark      string
	HostPreserved   bool
	SNIPreserved    bool
	TLSResult       string
	HTTPResult      string
	ContentResult   string
	ExternalIPHash  string
	ExternalCountry string
	StartedAt       time.Time
	CompletedAt     time.Time
}

type PathProofRequest struct {
	Route       config.Route
	Observation PathObservation
	Session     PathProofSession
}

type PathProofStart struct {
	Domain    string
	Route     config.Route
	StartedAt time.Time
}

type PathProofSession struct {
	StartedAt     time.Time
	CounterBefore uint64
	Metadata      map[string]string
	BeginError    string
}

type PathProofVerifier interface {
	Verify(context.Context, PathProofRequest) (evidence.RouteResult, error)
}

type PathProofStarter interface {
	Begin(context.Context, PathProofStart) (PathProofSession, error)
}

type Engine struct {
	proofVerifier PathProofVerifier
}

func NewEngine(verifier PathProofVerifier) *Engine {
	if verifier == nil {
		verifier = unavailableProofVerifier{}
	}
	return &Engine{proofVerifier: verifier}
}

type unavailableProofVerifier struct{}

func (unavailableProofVerifier) Verify(context.Context, PathProofRequest) (evidence.RouteResult, error) {
	return evidence.RouteResult{}, ErrPathEvidenceUnavailable
}

type errorProofVerifier struct{ err error }

func (v errorProofVerifier) Verify(context.Context, PathProofRequest) (evidence.RouteResult, error) {
	if v.err == nil {
		return evidence.RouteResult{}, ErrPathEvidenceUnavailable
	}
	return evidence.RouteResult{}, v.err
}

type BoundEvidenceVerifier struct {
	PlanPath        string
	EvidencePath    string
	Binding         artifact.Binding
	ManifestHash    string
	MaxAge          time.Duration
	AllowSimulation bool
}

func NewBoundEvidenceVerifier(planPath, evidencePath string, binding artifact.Binding, manifestHash string, allowSimulation bool) *BoundEvidenceVerifier {
	return &BoundEvidenceVerifier{
		PlanPath: planPath, EvidencePath: evidencePath, Binding: binding, ManifestHash: manifestHash,
		MaxAge: defaultProofMaxAge, AllowSimulation: allowSimulation,
	}
}

func (v *BoundEvidenceVerifier) Verify(_ context.Context, request PathProofRequest) (evidence.RouteResult, error) {
	if v == nil || v.PlanPath == "" || v.EvidencePath == "" || v.Binding.RevisionID == "" || v.ManifestHash == "" {
		return evidence.RouteResult{}, ErrPathEvidenceUnavailable
	}
	report, err := evidence.LoadAndVerify(v.PlanPath, v.EvidencePath, v.Binding, v.ManifestHash)
	if err != nil {
		return evidence.RouteResult{}, fmt.Errorf("bound_evidence_invalid: %w", err)
	}
	maxAge := v.MaxAge
	if maxAge <= 0 {
		maxAge = defaultProofMaxAge
	}
	for _, proof := range report.Routes {
		if proof.RouteTag != request.Route.Tag {
			continue
		}
		if proof.Simulation && !v.AllowSimulation {
			return evidence.RouteResult{}, errors.New("simulated_path_evidence_forbidden")
		}
		if proof.CheckedAt.Before(time.Now().UTC().Add(-maxAge)) || proof.CheckedAt.After(time.Now().UTC().Add(time.Minute)) {
			return evidence.RouteResult{}, errors.New("stale_path_evidence")
		}
		if err := matchObservation(proof, request.Observation); err != nil {
			return evidence.RouteResult{}, err
		}
		return proof, nil
	}
	return evidence.RouteResult{}, errors.New("route_path_evidence_missing")
}

func matchObservation(proof evidence.RouteResult, observed PathObservation) error {
	if proof.Domain == "" || !strings.EqualFold(proof.Domain, observed.Domain) {
		return errors.New("path_evidence_domain_mismatch")
	}
	if proof.DNSResolver != observed.DNSResolver {
		return errors.New("path_evidence_dns_resolver_mismatch")
	}
	if proof.ResolvedIP != "" && !containsIP(observed.ResolvedIPs, proof.ResolvedIP) {
		return errors.New("path_evidence_resolved_ip_mismatch")
	}
	if proof.ConnectedIP != observed.ConnectedIP {
		return errors.New("path_evidence_connected_ip_mismatch")
	}
	if proof.Transport != "" && proof.Transport != observed.Transport {
		return errors.New("path_evidence_transport_mismatch")
	}
	if proof.HostPreserved != observed.HostPreserved || proof.SNIPreserved != observed.SNIPreserved {
		return errors.New("path_evidence_host_or_sni_mismatch")
	}
	if proof.TLSResult != observed.TLSResult || proof.HTTPResult != observed.HTTPResult || proof.ContentResult != observed.ContentResult {
		return errors.New("path_evidence_application_mismatch")
	}
	if observed.ExternalIPHash != "" && proof.ExternalIPHash != observed.ExternalIPHash {
		return errors.New("path_evidence_external_ip_mismatch")
	}
	if observed.ExternalCountry != "" && !strings.EqualFold(proof.ExternalCountry, observed.ExternalCountry) {
		return errors.New("path_evidence_external_country_mismatch")
	}
	return nil
}

func containsIP(values []string, expected string) bool {
	expectedAddr, err := netip.ParseAddr(expected)
	if err != nil {
		return false
	}
	for _, value := range values {
		addr, err := netip.ParseAddr(value)
		if err == nil && addr == expectedAddr {
			return true
		}
	}
	return false
}

func (e *Engine) beginPathProof(ctx context.Context, domain string, route config.Route, startedAt time.Time) PathProofSession {
	session := PathProofSession{StartedAt: startedAt}
	starter, ok := e.proofVerifier.(PathProofStarter)
	if !ok {
		return session
	}
	started, err := starter.Begin(ctx, PathProofStart{Domain: domain, Route: route, StartedAt: startedAt})
	if err != nil {
		session.BeginError = err.Error()
		return session
	}
	if started.StartedAt.IsZero() {
		started.StartedAt = startedAt
	}
	return started
}

func (e *Engine) finishWithPathProof(ctx context.Context, _ *config.Config, route config.Route, result RouteResult, startedAt time.Time, session PathProofSession) RouteResult {
	observation := observationFromResult(route, result, startedAt)
	result.DNSResolver = observation.DNSResolver
	result.ResolvedIP = firstString(observation.ResolvedIPs)
	result.ConnectedIP = observation.ConnectedIP
	result.ConnectedPort = observation.ConnectedPort
	result.LocalIP = observation.LocalIP
	result.SocketMark = observation.SocketMark

	if session.BeginError != "" {
		result.PathVerified = false
		result.FailureStage = "path_evidence_begin"
		result.ReasonCode = proofErrorCode(errors.New(session.BeginError), route)
		if result.Status == "OK" || result.Status == "DEGRADED" || result.ApplicationStatus == "DROP" {
			result.Status = proofFailureStatus(errors.New(session.BeginError))
			reason := result.ReasonCode
			result.Reason = &reason
		}
		return result
	}

	proof, err := e.proofVerifier.Verify(ctx, PathProofRequest{Route: route, Observation: observation, Session: session})
	if err != nil {
		result.PathVerified = false
		result.FailureStage = "path_evidence"
		result.ReasonCode = proofErrorCode(err, route)
		if result.Status == "OK" || result.Status == "DEGRADED" || result.ApplicationStatus == "DROP" {
			result.Status = proofFailureStatus(err)
			reason := result.ReasonCode
			result.Reason = &reason
		}
		return result
	}

	result.PathVerified = true
	result.AdapterRevision = proof.AdapterRevision
	result.CandidateHash = proof.CandidateHash
	result.ArtifactManifestHash = proof.ArtifactManifestHash
	result.NFTMark = proof.NFTMark
	result.ConntrackMark = proof.ConntrackMark
	result.IPRulePriority = proof.IPRulePriority
	result.RouteTable = proof.RouteTable
	result.Interface = proof.Interface
	result.DNSResolver = proof.DNSResolver
	result.ResolvedIP = proof.ResolvedIP
	result.ConnectedIP = proof.ConnectedIP
	result.ConnectedPort = proof.ConnectedPort
	result.LocalIP = proof.LocalIP
	result.SocketMark = proof.SocketMark
	result.XrayOutboundTag = proof.XrayOutboundTag
	result.EvidenceSource = proof.EvidenceSource
	result.PathEvidence = &proof
	result.Simulation = proof.Simulation
	result.ReasonCode = proof.ReasonCode
	if result.ApplicationStatus == "DROP" {
		result.Status = "OK"
		result.ServiceOK = true
		reason := "drop_enforced"
		result.Reason = &reason
	}
	return result
}

func observationFromResult(route config.Route, result RouteResult, startedAt time.Time) PathObservation {
	observed := PathObservation{
		Domain: result.Domain, RouteTag: route.Tag, RouteType: route.Type,
		ExternalIPHash: result.ExternalIPHash, ExternalCountry: result.ExternalCountry,
		StartedAt: startedAt, CompletedAt: time.Now().UTC(),
	}
	for _, check := range result.Checks {
		if observed.DNSResolver == "" {
			observed.DNSResolver = check.DNSResolver
			observed.DNSProtocol = check.DNSProtocol
		}
		observed.ResolvedIPs = appendUnique(observed.ResolvedIPs, check.ResolvedIPs...)
		if check.Transport != "" {
			observed.Transport = check.Transport
			observed.SocketMark = check.SocketMark
			observed.HostPreserved = check.HostPreserved
			observed.SNIPreserved = check.SNIPreserved
		}
		if check.ConnectedIP != "" {
			observed.ConnectedIP = check.ConnectedIP
			observed.ConnectedPort = check.ConnectedPort
			observed.LocalIP = check.LocalIP
			observed.AddressFamily = check.AddressFamily
		}
		if check.HTTPOK {
			observed.HTTPResult = "OK"
		} else if check.HTTPCode > 0 {
			observed.HTTPResult = fmt.Sprintf("HTTP_%d", check.HTTPCode)
		}
		if check.TLSOK {
			observed.TLSResult = "OK"
		} else if check.TransportOK {
			observed.TLSResult = "NOT_APPLICABLE"
		}
		if check.ContentOK {
			observed.ContentResult = "OK"
		} else if check.HTTPOK {
			observed.ContentResult = "FAIL"
		}
	}
	if observed.HTTPResult == "" {
		observed.HTTPResult = "FAIL"
	}
	if observed.TLSResult == "" {
		observed.TLSResult = "FAIL"
	}
	if observed.ContentResult == "" {
		observed.ContentResult = "FAIL"
	}
	return observed
}

func appendUnique(dst []string, values ...string) []string {
	for _, value := range values {
		found := false
		for _, current := range dst {
			if current == value {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, value)
		}
	}
	return dst
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func proofErrorCode(err error, route config.Route) string {
	var statusErr *PathStatusError
	if errors.As(err, &statusErr) && statusErr.Code != "" {
		return statusErr.Code
	}
	if errors.Is(err, ErrPathEvidenceUnavailable) {
		if route.RequiresAdapter {
			return "route_requires_adapter_evidence"
		}
		return "route_path_evidence_unavailable"
	}
	code := strings.ToLower(err.Error())
	if i := strings.IndexByte(code, ':'); i >= 0 {
		code = code[:i]
	}
	code = strings.ReplaceAll(code, " ", "_")
	if code == "" {
		return "route_path_unverified"
	}
	return code
}

func proofFailureStatus(err error) string {
	var statusErr *PathStatusError
	if errors.As(err, &statusErr) && statusErr.Status != "" {
		return statusErr.Status
	}
	return "UNVERIFIED"
}
