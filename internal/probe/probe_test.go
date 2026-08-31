package probe

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"router-policy/internal/artifact"
	"router-policy/internal/config"
	"router-policy/internal/evidence"
)

func TestPreferIPv4KeepsEveryAddressAndMovesIPv4First(t *testing.T) {
	input := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("192.0.2.11"),
	}
	got := preferIPv4(input)
	want := []netip.Addr{input[1], input[3], input[0], input[2]}
	if len(got) != len(want) {
		t.Fatalf("address count changed: got %d want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("address %d = %s, want %s", index, got[index], want[index])
		}
	}
}

func TestRouteProbeTargetsAreFamilyFilteredAndBounded(t *testing.T) {
	input := make([]netip.Addr, 0, 12)
	for i := 1; i <= 8; i++ {
		input = append(input, netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)))
	}
	for i := 1; i <= 4; i++ {
		input = append(input, netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i)))
	}
	if got := routeProbeTargets(input, "ipv4"); len(got) != maxRouteProbeTargets {
		t.Fatalf("ipv4 route probe fan-out=%d want=%d", len(got), maxRouteProbeTargets)
	}
	if got := routeProbeTargets(input, "ipv6"); len(got) != maxRouteProbeTargets {
		t.Fatalf("ipv6 route probe fan-out=%d want=%d", len(got), maxRouteProbeTargets)
	}
}

func TestProbeRouteRejectsUnvalidatedProbeURLFanout(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	service := serviceWithProbe(srv.URL, []int{http.StatusNoContent}, "empty", nil)
	for i := len(service.ProbeURLs); i <= config.MaxProbeURLsPerService; i++ {
		service.ProbeURLs = append(service.ProbeURLs, config.ProbeCheck{
			Name:          fmt.Sprintf("extra-%d", i),
			URL:           srv.URL,
			Required:      true,
			ExpectedCodes: []int{http.StatusNoContent},
			BodyMode:      "empty",
		})
	}
	result := ProbeRoute(context.Background(), testConfig(), "example.test", "svc", service, config.Route{Type: "direct", Tag: "direct"})
	if result.ReasonCode != "probe_urls_exceed_bound" || result.ApplicationStatus != "NOT_RUN" || result.FailureStage != "preflight" {
		t.Fatalf("unvalidated probe fan-out was not rejected: %+v", result)
	}
	if requests != 0 {
		t.Fatalf("probe started network requests before enforcing the bound: %d", requests)
	}
}

func TestProbeHTTP200WithMarker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello GitHub"))
	}))
	defer srv.Close()

	result := ProbeRoute(context.Background(), testConfig(), "example.test", "svc", serviceWithProbe(srv.URL, []int{200}, "required", []string{"GitHub"}), config.Route{Type: "direct", Tag: "direct"})
	if result.Status != "UNVERIFIED" || result.ApplicationStatus != "OK" || !result.ServiceOK || result.PathVerified {
		t.Fatalf("application success without route proof must be UNVERIFIED, got %+v", result)
	}
	if !result.RouteLatencyAvailable || result.RouteLatencyMS <= 0 || result.LatencyMS != result.RouteLatencyMS {
		t.Fatalf("route latency was not measured separately: %+v", result)
	}
	if result.VerificationDurationMS < result.RouteLatencyMS {
		t.Fatalf("verification duration %dms is shorter than route latency %dms: %+v", result.VerificationDurationMS, result.RouteLatencyMS, result)
	}
	if len(result.Checks) != 1 || !result.Checks[0].EndToEndLatencyAvailable || result.Checks[0].EndToEndLatencyMS <= 0 {
		t.Fatalf("successful HTTP check did not record end-to-end network evidence: %+v", result)
	}
}

func TestProbe403IsTypedAsWAFOrRateLimitNotRegionalBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	result := ProbeRoute(context.Background(), testConfig(), "example.test", "svc", serviceWithProbe(srv.URL, []int{http.StatusOK}, "optional", nil), config.Route{Type: "direct", Tag: "direct"})
	if result.Status != "WAF_OR_RATE_LIMIT" || result.RegionalBlock || result.ServiceOK {
		t.Fatalf("403 was misclassified as a service success/geo block: %+v", result)
	}
	if len(result.Checks) != 1 || !result.Checks[0].WAFOrRateLimit {
		t.Fatalf("typed 403 evidence missing: %+v", result)
	}
}

type fixedProofVerifier struct {
	proof evidence.RouteResult
}

func (v fixedProofVerifier) Verify(context.Context, PathProofRequest) (evidence.RouteResult, error) {
	return v.proof, nil
}

func TestPathVerificationDurationIsNotRouteLatency(t *testing.T) {
	engine := NewEngine(fixedProofVerifier{proof: evidence.RouteResult{
		RouteLatencyMS: 74, RouteLatencyAvailable: true, LatencyMS: 74,
		ReasonCode: "verified", Status: "OK", Simulation: true,
	}})
	started := time.Now().Add(-250 * time.Millisecond)
	result := engine.finishWithPathProof(context.Background(), testConfig(), config.Route{Type: "direct", Tag: "direct"}, RouteResult{
		Domain: "example.test", Route: "direct", RouteType: "direct", Status: "OK", ApplicationStatus: "OK",
		ServiceOK: true, RouteLatencyMS: 74, RouteLatencyAvailable: true,
	}, started, PathProofSession{StartedAt: started})
	if result.LatencyMS != 74 || result.RouteLatencyMS != 74 || !result.RouteLatencyAvailable {
		t.Fatalf("route latency was overwritten by verification duration: %+v", result)
	}
	if result.VerificationDurationMS < 200 {
		t.Fatalf("verification duration did not cover orchestration time: %+v", result)
	}
	if result.VerificationDurationMS == result.LatencyMS {
		t.Fatalf("latency and verification duration remain indistinguishable: %+v", result)
	}
}

func TestPathProofFailureNormalizesCaseVariantSuccessStatus(t *testing.T) {
	engine := NewEngine(fixedProofVerifier{})
	result := engine.finishWithPathProof(context.Background(), testConfig(), config.Route{Type: "direct", Tag: "direct"}, RouteResult{
		Domain: "example.test", Route: "direct", RouteType: "direct", Status: "ok", ApplicationStatus: "OK",
		ServiceOK: true, PathVerified: true,
	}, time.Now(), PathProofSession{BeginError: "missing path evidence"})
	if result.Status == "ok" || result.PathVerified || result.FailureStage != "path_evidence_begin" {
		t.Fatalf("case-variant success status survived path-proof failure: %+v", result)
	}
}

func TestFinalizeCheckResultDoesNotDeriveE2EFromVerificationDuration(t *testing.T) {
	result := finalizeCheckResult(CheckResult{
		Status: "ok", RouteLatencyMS: 12, RouteLatencyAvailable: true,
	}, time.Now().Add(-20*time.Millisecond))
	if result.EndToEndLatencyAvailable || result.EndToEndLatencyMS != 0 {
		t.Fatalf("verification duration was incorrectly exposed as end-to-end latency: %+v", result)
	}
	if result.VerificationDurationMS <= 0 {
		t.Fatalf("verification duration was not recorded: %+v", result)
	}
}

func TestFinalizeCheckResultPreservesMeasuredE2E(t *testing.T) {
	result := finalizeCheckResult(CheckResult{
		Status: "ok", RouteLatencyMS: 12, RouteLatencyAvailable: true,
		EndToEndLatencyMS: 37, EndToEndLatencyAvailable: true,
	}, time.Now().Add(-20*time.Millisecond))
	if !result.EndToEndLatencyAvailable || result.EndToEndLatencyMS != 37 {
		t.Fatalf("measured end-to-end evidence was overwritten: %+v", result)
	}
}

func TestComposeEndToEndLatencyDoesNotAccumulatePreviousAttempts(t *testing.T) {
	// The first target may have timed out before a second target succeeds. The
	// comparable metric is DNS once plus the successful attempt, not the sum of
	// all target attempts.
	got, ok := composeEndToEndLatency(12, 85)
	if !ok || got != 97 {
		t.Fatalf("unexpected per-attempt end-to-end latency: got=%d ok=%v", got, ok)
	}
}

func TestProbeHTTP204EmptyBodyIsOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()

	result := ProbeRoute(context.Background(), testConfig(), "example.test", "svc", serviceWithProbe(srv.URL, []int{204}, "empty", nil), config.Route{Type: "direct", Tag: "direct"})
	if result.Status != "UNVERIFIED" || result.ApplicationStatus != "OK" {
		t.Fatalf("expected application OK but unverified route for 204, got %+v", result)
	}
}

func TestProbeUnexpected403Fails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	result := ProbeRoute(context.Background(), testConfig(), "example.test", "svc", serviceWithProbe(srv.URL, []int{200}, "required", nil), config.Route{Type: "direct", Tag: "direct"})
	if result.Status == "OK" {
		t.Fatalf("403 must not be globally OK: %+v", result)
	}
}

func TestProbeExpected401IsAuthenticationRequiredNotServiceSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte("missing api key"))
	}))
	defer srv.Close()

	result := ProbeRoute(context.Background(), testConfig(), "example.test", "svc", serviceWithProbe(srv.URL, []int{401}, "required", nil), config.Route{Type: "direct", Tag: "direct"})
	if result.Status != "AUTH_REQUIRED" || result.ApplicationStatus != "AUTH_REQUIRED" || result.ServiceOK {
		t.Fatalf("401 must remain an authentication result, not service success: %+v", result)
	}
}

func TestProbeAllowsExplicitUnauthenticated401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte("public endpoint requires a token"))
	}))
	defer srv.Close()

	check := serviceWithProbe(srv.URL, []int{401}, "optional", nil)
	check.ProbeURLs[0].AllowUnauthenticated = true
	result := ProbeRoute(context.Background(), testConfig(), "example.test", "svc", check, config.Route{Type: "direct", Tag: "direct"})
	if result.ApplicationStatus != "OK" || !result.ServiceOK || result.AuthenticationRequired || len(result.Checks) != 1 || result.Checks[0].Status != "OK" {
		t.Fatalf("explicit unauthenticated 401 should be a valid service check: %+v", result)
	}
}

func TestProbeRegionalBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte("not available in your country"))
	}))
	defer srv.Close()

	result := ProbeRoute(context.Background(), testConfig(), "example.test", "svc", serviceWithProbe(srv.URL, []int{200}, "required", nil), config.Route{Type: "direct", Tag: "direct"})
	if result.Status != "REGION_BLOCK" || !result.RegionalBlock {
		t.Fatalf("expected REGION_BLOCK, got %+v", result)
	}
}

func TestProbeHTTP451IsTSPU(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(451)
		_, _ = w.Write([]byte("legal block"))
	}))
	defer srv.Close()

	result := ProbeRoute(context.Background(), testConfig(), "example.test", "svc", serviceWithProbe(srv.URL, []int{200}, "optional", nil), config.Route{Type: "direct", Tag: "direct"})
	if result.Status != "SUSPECTED_TSPU" || !result.SuspectedTSPU {
		t.Fatalf("expected SUSPECTED_TSPU, got %+v", result)
	}
}

func TestSmartDNSConnectsToResolvedIP(t *testing.T) {
	seenHost := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost <- r.Host
		w.WriteHeader(200)
		_, _ = w.Write([]byte("smart ok"))
	}))
	defer srv.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	dnsAddr, closeDNS := startTestDNSServer(t, net.ParseIP("127.0.0.1"))
	defer closeDNS()

	checkURL := "http://smart.test:" + port + "/"
	result := ProbeRoute(context.Background(), testConfig(), "smart.test", "svc", serviceWithProbe(checkURL, []int{200}, "required", []string{"smart ok"}), config.Route{
		Type:                "smart_dns",
		Tag:                 "test-smart-dns",
		DNSServer:           dnsAddr,
		ConnectToResolvedIP: true,
	})
	if result.Status != "UNVERIFIED" || result.ApplicationStatus != "OK" {
		t.Fatalf("Smart DNS application success without adapter binding must be UNVERIFIED, got %+v", result)
	}
	if len(result.Checks) == 0 || result.Checks[0].ConnectedIP != "127.0.0.1" {
		t.Fatalf("expected connection to smart DNS IP, got %+v", result.Checks)
	}
	select {
	case host := <-seenHost:
		if !strings.HasPrefix(host, "smart.test") {
			t.Fatalf("expected Host to preserve original domain, got %q", host)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive request")
	}
}

func TestSmartDNSGEOPathRequiresEgressConsensus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("regional content"))
	}))
	defer srv.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	dnsAddr, closeDNS := startTestDNSServer(t, net.ParseIP("127.0.0.1"))
	defer closeDNS()

	service := serviceWithProbe("http://smart.test:"+port+"/", []int{http.StatusOK}, "required", []string{"regional content"})
	service.Category = "GEO_LOCKED"
	service.RequireNonRUEgress = true
	service.AllowedPaths = []string{"smart_dns", "drop"}
	result := ProbeRoute(context.Background(), testConfig(), "smart.test", "geo", service, config.Route{
		Type: "smart_dns", Tag: "smart", DNSServer: dnsAddr, ConnectToResolvedIP: true,
	})
	if result.ServiceOK || result.Status == "OK" {
		t.Fatalf("Smart DNS GEO path without egress evidence was accepted: %+v", result)
	}
	if result.EgressReason == "" {
		t.Fatalf("missing egress evidence did not produce a diagnostic: %+v", result)
	}
}

func TestSmartDNSRejectsPrivateAnswerOutsideTestMode(t *testing.T) {
	dnsAddr, closeDNS := startTestDNSServer(t, net.ParseIP("127.0.0.1"))
	defer closeDNS()
	cfg := testConfig()
	cfg.Platform.Target = "flint2"
	result := ProbeRoute(context.Background(), cfg, "smart.test", "svc", serviceWithProbe("https://smart.test/", []int{200}, "optional", nil), config.Route{
		Type: "smart_dns", Tag: "smart", DNSServer: dnsAddr, ConnectToResolvedIP: true,
	})
	if len(result.Checks) != 1 || result.Checks[0].Reason != "smart_dns_unsafe_answer" || result.ApplicationStatus != "FAIL" {
		t.Fatalf("unsafe Smart DNS answer was not rejected: %+v", result)
	}
}

func TestSmartDNSRequiresConnectionToReturnedAddress(t *testing.T) {
	dnsAddr, closeDNS := startTestDNSServer(t, net.ParseIP("127.0.0.1"))
	defer closeDNS()
	result := ProbeRoute(context.Background(), testConfig(), "smart.test", "svc", serviceWithProbe("https://smart.test/", []int{200}, "optional", nil), config.Route{
		Type: "smart_dns", Tag: "smart", DNSServer: dnsAddr,
	})
	if len(result.Checks) != 1 || !strings.Contains(result.Checks[0].Reason, "smart_dns_connect_to_answer_required") {
		t.Fatalf("Smart DNS route without connect-to-answer was accepted: %+v", result)
	}
}

func TestSmartDNSFallsBackToTCPWhenUDPIsTruncated(t *testing.T) {
	address, closeDNS := startTruncatedUDPDNSServer(t, net.ParseIP("203.0.113.10"))
	defer closeDNS()
	addrs, protocol, err := queryDNS(context.Background(), address, "smart.test")
	if err != nil {
		t.Fatal(err)
	}
	if protocol != "tcp" || len(addrs) != 1 || addrs[0].String() != "203.0.113.10" {
		t.Fatalf("unexpected TCP fallback result: protocol=%s addrs=%v", protocol, addrs)
	}
}

func TestSmartDNSRouteUsesFallbackResolverWhenPrimaryFails(t *testing.T) {
	primaryConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	primary := primaryConn.LocalAddr().String()
	primaryServer := &dns.Server{PacketConn: primaryConn, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		_ = writer.WriteMsg(response)
	})}
	go func() { _ = primaryServer.ActivateAndServe() }()
	defer primaryServer.Shutdown()
	fallback, closeDNS := startTestDNSServer(t, net.ParseIP("203.0.113.10"))
	defer closeDNS()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, resolver, _, err := resolveForRoute(ctx, testConfig(), config.Route{
		Type: "smart_dns", Tag: "pair", DNSServer: primary, DNSFallbackServer: fallback, ConnectToResolvedIP: true,
	}, "smart.test")
	if err != nil {
		t.Fatal(err)
	}
	if resolver != fallback || len(addrs) != 1 || addrs[0].String() != "203.0.113.10" {
		t.Fatalf("fallback resolver was not selected: resolver=%q addrs=%v", resolver, addrs)
	}
}

func TestDNSRejectsUnrelatedAddressRecord(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion("smart.test.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "evil.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.10").To4()}}
	if _, _, err := validateDNSResponse(request, response, "smart.test", dns.TypeA, "udp"); err == nil {
		t.Fatal("unrelated DNS answer was accepted")
	}
}

func TestBoundPathEvidenceAllowsVerifiedDirectResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("bound proof"))
	}))
	defer srv.Close()

	verifier := writeBoundDirectEvidence(t, "example.test", "::ffff:127.0.0.1", "127.0.0.1", 100)
	route := config.Route{Type: "direct", Tag: "direct", Mark: "0x41"}
	result := NewEngine(verifier).ProbeRoute(context.Background(), testConfig(), "example.test", "svc", serviceWithProbe(srv.URL, []int{200}, "required", []string{"bound proof"}), route)
	if result.Status != "OK" || !result.PathVerified || result.AdapterRevision == "" || result.RouteTable != 100 {
		t.Fatalf("expected application and bound path proof to produce OK, got %+v", result)
	}
	if result.PathEvidence == nil || result.PathEvidence.RouteTag != "direct" || !result.PathEvidence.DirectBypassXray || !result.PathEvidence.DirectBypassZapret {
		t.Fatalf("canonical path evidence was not exposed by the probe result: %+v", result.PathEvidence)
	}
}

func TestWrongRouteEvidenceCannotProduceOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("bound proof"))
	}))
	defer srv.Close()

	verifier := writeBoundDirectEvidence(t, "example.test", "::ffff:127.0.0.1", "127.0.0.1", 200)
	result := NewEngine(verifier).ProbeRoute(context.Background(), testConfig(), "example.test", "svc", serviceWithProbe(srv.URL, []int{200}, "required", []string{"bound proof"}), config.Route{Type: "direct", Tag: "direct", Mark: "0x41"})
	if result.Status != "UNVERIFIED" || result.PathVerified {
		t.Fatalf("wrong route table evidence was accepted: %+v", result)
	}
}

func TestZapretRouteNameWithoutFlowEvidenceIsUnverified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ordinary direct response"))
	}))
	defer srv.Close()

	result := ProbeRoute(context.Background(), testConfig(), "example.test", "svc", serviceWithProbe(srv.URL, []int{200}, "required", nil), config.Route{Type: "zapret", Tag: "zapret"})
	if result.Status != "UNVERIFIED" || result.ApplicationStatus != "OK" {
		t.Fatalf("a route named Zapret must not pass as proof: %+v", result)
	}
}

func testConfig() *config.Config {
	return &config.Config{
		Version:  2,
		Platform: config.Platform{Target: "test"},
		Policy:   config.Policy{MaxProbeSeconds: 5},
		GeoIP:    config.GeoIP{FailCountry: "UNKNOWN"},
	}
}

func serviceWithProbe(rawURL string, codes []int, bodyMode string, markers []string) config.Service {
	return config.Service{
		Category:           "DIRECT_PREFERRED",
		AllowedPaths:       []string{"direct", "smart_dns"},
		RequireNonRUEgress: false,
		ProbeURLs: []config.ProbeCheck{{
			Name:           "test",
			URL:            rawURL,
			Required:       true,
			ExpectedCodes:  codes,
			BodyMode:       bodyMode,
			SuccessMarkers: markers,
		}},
	}
}

func writeBoundDirectEvidence(t *testing.T, domain, resolvedIP, connectedIP string, actualTable int) *BoundEvidenceVerifier {
	t.Helper()
	root := t.TempDir()
	binding := artifact.Binding{TransactionID: "tx_0011223344556677", RevisionID: "rev_2_001122334455", CandidateHash: "sha256:candidate"}
	required := artifact.RouteProof{Tag: "direct", Type: "direct", Mark: "0x41", Table: 100, RulePriority: 10010, RequiresIPv4: true}
	plan := artifact.VerificationPlan{Binding: binding, RequiredRouteProof: []artifact.RouteProof{required}}
	proof := evidence.RouteResult{
		Domain: domain, RouteTag: "direct", RouteType: "direct", AdapterRevision: binding.RevisionID,
		CandidateHash: binding.CandidateHash, ArtifactManifestHash: "sha256:manifest", NFTMark: "0x41", ConntrackMark: "0x41",
		IPRulePriority: 10010, RouteTable: actualTable, Interface: "wan", DNSResolver: "system", ResolvedIP: resolvedIP, ConnectedIP: connectedIP,
		LocalIP: "127.0.0.1", AddressFamily: "ipv4", Transport: "direct", HostPreserved: true, SNIPreserved: true,
		DirectBypassXray: true, DirectBypassZapret: true, InheritedMarkCleared: true, IPv4Verified: true,
		TLSResult: "NOT_APPLICABLE", HTTPResult: "OK", ContentResult: "OK", ReasonCode: "verified", Status: "OK",
		EvidenceSource: "test-bound-report", Simulation: true, CheckedAt: time.Now().UTC(),
	}
	report := evidence.Report{Binding: binding, ArtifactManifestHash: "sha256:manifest", Routes: []evidence.RouteResult{proof}, CheckedAt: time.Now().UTC()}
	planPath := filepath.Join(root, "verification-plan.json")
	evidencePath := filepath.Join(root, "route-evidence.json")
	writeJSONFile(t, planPath, plan)
	writeJSONFile(t, evidencePath, report)
	return NewBoundEvidenceVerifier(planPath, evidencePath, binding, "sha256:manifest", true)
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func startTestDNSServer(t *testing.T, ip net.IP) (string, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			resp := buildDNSAResponse(req, ip.To4())
			_, _ = conn.WriteTo(resp, addr)
		}
	}()
	return conn.LocalAddr().String(), func() {
		_ = conn.Close()
		<-done
	}
}

func startTruncatedUDPDNSServer(t *testing.T, ip net.IP) (string, func()) {
	t.Helper()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tcpListener.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		if strings.HasPrefix(w.LocalAddr().Network(), "udp") {
			response.Truncated = true
			_ = w.WriteMsg(response)
			return
		}
		if len(request.Question) == 1 && request.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: ip.To4()}}
		}
		_ = w.WriteMsg(response)
	})
	udpServer := &dns.Server{PacketConn: udpConn, Handler: handler}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: handler}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	return net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	}
}

func buildDNSAResponse(req []byte, ip net.IP) []byte {
	resp := make([]byte, 0, len(req)+16)
	resp = append(resp, req[0], req[1], 0x81, 0x80)
	resp = append(resp, req[4], req[5])
	resp = append(resp, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
	question := req[12:]
	resp = append(resp, question...)
	resp = append(resp, 0xc0, 0x0c)
	resp = append(resp, 0x00, 0x01, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3c)
	resp = append(resp, 0x00, 0x04)
	resp = append(resp, ip...)
	binary.BigEndian.PutUint16(resp[6:8], 1)
	return resp
}
