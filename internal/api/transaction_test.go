package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"router-policy/internal/adapter"
	"router-policy/internal/artifact"
	"router-policy/internal/auth"
	"router-policy/internal/config"
	"router-policy/internal/managementproof"
	"router-policy/internal/planner"
	"router-policy/internal/platform"
	"router-policy/internal/probe"
)

type artifactDiagnosticsTestProvider struct {
	platform.DevelopmentMockProvider
	diagnostics platform.NetworkDiagnostics
	simulation  bool
}

func (p artifactDiagnosticsTestProvider) Name() string     { return "artifact-diagnostics-test-provider" }
func (p artifactDiagnosticsTestProvider) Simulation() bool { return p.simulation }
func (p artifactDiagnosticsTestProvider) NetworkDiagnostics(*config.Config) platform.NetworkDiagnostics {
	return p.diagnostics
}

func TestUnsupportedOperationBlocksValidate(t *testing.T) {
	cfg := testAPIConfig(t)
	_, _, _, validation := buildCandidate(cfg, []ChangeOp{{Type: "merge", Path: "/services/github/category", Value: "GEO_LOCKED"}})
	if !hasValidationError(validation) {
		t.Fatalf("unsupported operation was not rejected: %+v", validation)
	}
}

func TestImmutableAdapterPathBlocksValidate(t *testing.T) {
	cfg := testAPIConfig(t)
	_, _, _, validation := buildCandidate(cfg, []ChangeOp{{Type: "set", Path: "/openwrt/adapter", Value: "/tmp/evil"}})
	if !hasValidationError(validation) {
		t.Fatalf("immutable helper path was editable: %+v", validation)
	}
}

func TestManagedXrayActivationFieldsAreEditable(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Xray.InitScript = "/etc/init.d/router-policy-xray"
	candidate, _, diff, validation := buildCandidate(cfg, []ChangeOp{
		{Type: "set", Path: "/xray/activation_mode", Value: "managed"},
		{Type: "set", Path: "/xray/subscription_secret_file", Value: "/etc/router-policy/secrets/vpn-subscription-url"},
	})
	if hasValidationError(validation) {
		t.Fatalf("managed Xray activation fields were rejected: %+v", validation)
	}
	if candidate == nil || candidate.Xray.ActivationMode != "managed" || len(diff) == 0 {
		t.Fatalf("managed Xray activation was not applied: candidate=%+v diff=%+v", candidate, diff)
	}
}

func TestImmutableXrayBinaryPathBlocksValidate(t *testing.T) {
	cfg := testAPIConfig(t)
	_, _, _, validation := buildCandidate(cfg, []ChangeOp{{Type: "set", Path: "/xray/binary", Value: "/tmp/xray"}})
	if !hasValidationError(validation) {
		t.Fatalf("immutable Xray binary path was editable: %+v", validation)
	}
}

func TestFlint2PersistentStatePathsAreEditableTogether(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.Platform.Target = "glinet-flint2"
	cfg.Storage = config.Storage{StateDir: "/var/lib/router-policy", RuntimeDir: "/tmp/router-policy", Database: "/var/lib/router-policy/router-policy.bbolt"}
	cfg.Xray.LastGoodConfig = "/var/lib/router-policy/last-good/xray.json"
	cfg.GeoIP.Database = "/var/lib/router-policy/geoip/user-country.mmdb"
	candidate, _, _, validation := buildCandidate(cfg, []ChangeOp{
		{Type: "set", Path: "/storage/state_dir", Value: "/etc/router-policy/state"},
		{Type: "set", Path: "/storage/database", Value: "/etc/router-policy/state/router-policy.bbolt"},
		{Type: "set", Path: "/xray/last_good_config", Value: "/etc/router-policy/state/last-good/xray.json"},
		{Type: "set", Path: "/geoip/database", Value: "/etc/router-policy/state/geoip/user-country.mmdb"},
	})
	if hasValidationError(validation) {
		t.Fatalf("persistent state migration was rejected: %+v", validation)
	}
	if candidate == nil || candidate.Storage.StateDir != "/etc/router-policy/state" || candidate.GeoIP.Database != "/etc/router-policy/state/geoip/user-country.mmdb" {
		t.Fatalf("persistent state migration was not applied: %+v", candidate)
	}
}

func TestOverrideChangeSetPersistsFullCanonicalCandidate(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()

	body := `{"title":"Route GitHub through Smart DNS","base_version":1,"operations":[{"type":"set","path":"/overrides","value":[{"id":"github-smart","scope":"exact_domain","domain":"GITHUB.COM.","route_type":"smart_dns","route_tag":"smart"}]}]}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/changes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status=%d body=%s", resp.StatusCode, raw)
	}
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env.Data)
	var cs ChangeSet
	if err := json.Unmarshal(raw, &cs); err != nil {
		t.Fatal(err)
	}
	changeID := cs.ID
	cs, status := postAction(t, client, csrf, ts.URL, changeID, "validate", `{}`)
	if status != http.StatusOK || cs.State != "validated" {
		var persisted ChangeSet
		_ = srv.store.LoadJSON("changes", changeID, &persisted)
		t.Fatalf("validate status=%d change=%+v persisted_validation=%+v", status, cs, persisted.Validation)
	}

	var candidate candidateRecord
	if err := srv.store.LoadJSON("candidates", cs.ID, &candidate); err != nil {
		t.Fatal(err)
	}
	if len(candidate.Config.Overrides) != 1 {
		t.Fatalf("full candidate lost override: %+v", candidate.Config.Overrides)
	}
	override := candidate.Config.Overrides[0]
	if override.ID != "github-smart" || override.Domain != "github.com" || override.RouteType != "smart_dns" || override.RouteTag != "smart" {
		t.Fatalf("persisted override is not canonical: %+v", override)
	}
	if _, ok := candidate.Config.Services["github"]; !ok || len(candidate.Config.Routes) != 3 {
		t.Fatalf("candidate is a partial patch instead of the full config: %+v", candidate.Config)
	}
	if candidate.Hash != cs.CandidateHash || candidate.Hash != hashBytes(candidate.Canonical) {
		t.Fatalf("candidate hash is not bound to full canonical config: record=%q change=%q canonical=%q", candidate.Hash, cs.CandidateHash, hashBytes(candidate.Canonical))
	}
	fileBytes, err := os.ReadFile(cs.CandidatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(fileBytes), candidate.Canonical) {
		t.Fatal("atomic candidate file differs from the canonical candidate stored in bbolt")
	}
	foundDiff := false
	for _, op := range cs.Diff {
		if strings.HasPrefix(op.Path, "/overrides") {
			foundDiff = true
			break
		}
	}
	if !foundDiff {
		t.Fatalf("active-to-candidate diff omitted override: %+v", cs.Diff)
	}
}

func TestCreateChangeSetRejectsEmptyOperations(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/changes", strings.NewReader(`{"title":"Empty change","base_version":1,"operations":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	var env ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Code != "operations_required" {
		t.Fatalf("unexpected error envelope: %+v", env.Error)
	}
}

func TestFlowOffloadingDisableChangeSetIsExplicitlyWarned(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()

	body := `{"title":"Disable flow offloading","base_version":1,"operations":[{"type":"set","path":"/openwrt/flow_offloading_policy","value":"disable"}]}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/changes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status %d", resp.StatusCode)
	}
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env.Data)
	var cs ChangeSet
	if err := json.Unmarshal(raw, &cs); err != nil {
		t.Fatal(err)
	}
	changeID := cs.ID
	cs, status := postAction(t, client, csrf, ts.URL, changeID, "validate", `{}`)
	if status != http.StatusOK || cs.State != "validated" || !cs.ArtifactsReady {
		var persisted ChangeSet
		_ = srv.store.LoadJSON("changes", changeID, &persisted)
		t.Fatalf("flow offloading ChangeSet did not validate: status=%d change=%+v persisted_validation=%+v", status, cs, persisted.Validation)
	}
	warned := false
	for _, validation := range cs.Validation {
		if validation.Level == "warning" && validation.Code == "flow_offloading_disable_planned" {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatalf("explicit flow offloading change lacks warning: %+v", cs.Validation)
	}
	var candidate candidateRecord
	if err := srv.store.LoadJSON("candidates", cs.ID, &candidate); err != nil {
		t.Fatal(err)
	}
	if candidate.Config.OpenWrt.FlowOffloadingPolicy != "disable" {
		t.Fatalf("candidate lost explicit flow offloading policy: %+v", candidate.Config.OpenWrt)
	}
}

func TestServiceClassifyCanExplicitlyDisableFlowOffloading(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	srv.domainChecker = func(_ context.Context, _ *config.Config, domain, serviceID string, _ planner.Options) (planner.DomainCheck, error) {
		return planner.DomainCheck{
			Domain: domain, Service: serviceID, Status: "SELECTED",
			Selected: &probe.RouteResult{Route: "smart", RouteType: "smart_dns", Status: "OK", ServiceOK: true, PathVerified: true},
		}, nil
	}

	body := `{"domain":"example.com","category":"GEO_LOCKED","allowed_paths":["smart_dns","vless","drop"],"base_version":1,"allow_disable_flow_offloading":true}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/services/classify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("classify status=%d body=%s", resp.StatusCode, raw)
	}
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env.Data)
	var result struct {
		Change ChangeSet `json:"change"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	change := result.Change
	if len(change.Operations) != 2 {
		t.Fatalf("expected service and flow-offloading operations, got %+v", change.Operations)
	}
	foundService := false
	foundFlowOffloading := false
	for _, operation := range change.Operations {
		switch operation.Path {
		case "/services/user_example_com":
			foundService = true
		case "/openwrt/flow_offloading_policy":
			foundFlowOffloading = operation.Value == "disable"
		}
	}
	if !foundService || !foundFlowOffloading {
		t.Fatalf("explicit auto-fix operations are incomplete: %+v", change.Operations)
	}
}

func TestMissingNetworkDiagnosticsRequiresDeviceBeforeAdapter(t *testing.T) {
	cfg := testAPIConfig(t)
	if err := os.Remove(filepath.Join(cfg.Storage.StateDir, "diagnostics", "network.json")); err != nil {
		t.Fatal(err)
	}
	fake := newFakeAdapter()
	srv, ts, client, csrf, _ := newTransactionHTTP(t, cfg, fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	if cs.ArtifactsReady || cs.ArtifactBlockReason != "network_diagnostics_missing" {
		t.Fatalf("candidate without diagnostics was marked deployable: %+v", cs)
	}
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "requires_device" || fake.callCount("prepare") != 0 || fake.callCount("rollback") != 0 {
		t.Fatalf("adapter was called for unresolved ip routes: status=%d change=%+v calls=%v", status, cs, fake.calls)
	}
}

func TestProductionRefusesSimulatedNetworkDiagnostics(t *testing.T) {
	cfg := testAPIConfig(t)
	fake := newFakeAdapter()
	provider := artifactDiagnosticsTestProvider{diagnostics: testArtifactNetworkDiagnostics(true), simulation: true}
	srv, ts, client, csrf, _ := newTransactionHTTPWithProvider(t, cfg, fake, false, provider)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	if cs.ArtifactsReady || cs.ArtifactBlockReason != "network_diagnostics_stale_or_unverified" {
		t.Fatalf("production did not reject simulated diagnostics during generation: %+v", cs)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.Storage.StateDir, "diagnostics", "network.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"simulation":true`) || !strings.Contains(string(raw), `"reason":"simulation_not_allowed_in_production"`) {
		t.Fatalf("production simulation refusal was not persisted honestly: %s", raw)
	}
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "requires_device" || fake.callCount("prepare") != 0 {
		t.Fatalf("production accepted simulated diagnostics: status=%d change=%+v calls=%v", status, cs, fake.calls)
	}
}

func TestValidateRefreshesProviderDiagnosticsAndBindsGeneratedArtifacts(t *testing.T) {
	cfg := testAPIConfig(t)
	fake := newFakeAdapter()
	provider := artifactDiagnosticsTestProvider{diagnostics: testArtifactNetworkDiagnostics(false), simulation: false}
	srv, ts, client, csrf, _ := newTransactionHTTPWithProvider(t, cfg, fake, false, provider)
	defer srv.Close()
	defer ts.Close()

	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	if !cs.ArtifactsReady || cs.ArtifactsSimulation || cs.ArtifactBlockReason != "" {
		t.Fatalf("verified provider diagnostics did not produce deployable artifacts: %+v", cs)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.Storage.StateDir, "diagnostics", "network.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted platform.NetworkDiagnostics
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Source != "hardware-test-provider" || persisted.Status != "VERIFIED" || persisted.WANInterface != "eth1" {
		t.Fatalf("provider diagnostics were not persisted: %+v", persisted)
	}

	var transaction transactionRecord
	if err := srv.store.LoadJSON("transactions", cs.TransactionID, &transaction); err != nil {
		t.Fatal(err)
	}
	binding := artifact.Binding{TransactionID: cs.TransactionID, RevisionID: cs.RevisionID, CandidateHash: cs.CandidateHash}
	manifest, err := artifact.Verify(transaction.Transaction.ArtifactRoot, binding, cs.ArtifactManifestHash)
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.DeploymentReady {
		t.Fatalf("manifest is not bound to the validated ChangeSet: %+v", manifest)
	}
	plan, err := artifact.LoadIPPlan(filepath.Join(transaction.Transaction.ArtifactRoot, artifact.IPPlanFile), binding)
	if err != nil {
		t.Fatal(err)
	}
	diagnosticsHash := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	if plan.DiagnosticsHash != diagnosticsHash || plan.DiagnosticsSource != "hardware-test-provider" {
		t.Fatalf("ip plan is not bound to provider diagnostics: plan=%+v want_hash=%s", plan, diagnosticsHash)
	}
}

func TestSkippedApplyRequiresDeviceAndCannotConfirm(t *testing.T) {
	fake := newFakeAdapter()
	fake.status["apply_candidate"] = "SKIPPED"
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "requires_device" {
		t.Fatalf("SKIPPED became an applied state: status=%d change=%+v", status, cs)
	}
	_, status = postAction(t, client, csrf, ts.URL, cs.ID, "confirm", `{}`)
	if status != http.StatusConflict || fake.callCount("commit") != 0 {
		t.Fatalf("requires_device transaction was confirmable: status=%d", status)
	}
}

func TestFilesystemAdapterCannotReachAwaitingConfirmation(t *testing.T) {
	cfg := testAPIConfig(t)
	local := adapter.NewFilesystem(cfg)
	srv, ts, client, csrf, _ := newTransactionHTTP(t, cfg, local)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "requires_device" || cs.DataPlaneVerified || cs.ManagementVerified {
		t.Fatalf("filesystem adapter falsely applied a candidate: status=%d change=%+v", status, cs)
	}
}

func TestUnverifiedVerificationRollsBackAppliedCandidate(t *testing.T) {
	fake := newFakeAdapter()
	fake.status["verify_management_path"] = "UNVERIFIED"
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "requires_device" || fake.callCount("rollback") != 1 {
		t.Fatalf("UNVERIFIED verification left applied data plane active: status=%d change=%+v", status, cs)
	}
	if cs.ManagementVerified || cs.DataPlaneVerified || fake.callCount("verify_data_plane") != 0 {
		t.Fatalf("verification continued after management became UNVERIFIED: %+v", cs)
	}
}

func TestManagementPathLossAfterApplyRollsBackAutomatically(t *testing.T) {
	fake := newFakeAdapter()
	fake.fail["verify_management_path"] = true
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "rolled_back" || fake.callCount("rollback") != 1 {
		t.Fatalf("management path loss did not trigger rollback: status=%d change=%+v", status, cs)
	}
	if fake.callCount("verify_data_plane") != 0 || cs.ManagementVerified || cs.DataPlaneVerified {
		t.Fatalf("data-plane verification continued after management loss: %+v", cs)
	}
}

func TestRollbackActionCallsAdapterRollback(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, _ = postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "rollback", `{}`)
	if status != http.StatusOK || cs.State != "rolled_back" || fake.callCount("rollback") != 1 {
		t.Fatalf("rollback did not reach adapter: status=%d change=%+v", status, cs)
	}
}

func TestCorruptRollbackCapabilityIsForbidden(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, _ = postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	var record transactionRecord
	if err := srv.store.LoadJSON("transactions", cs.TransactionID, &record); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record.Transaction.CapabilityPath, []byte("deadbeef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, status := postAction(t, client, csrf, ts.URL, cs.ID, "rollback", `{}`)
	if status != http.StatusForbidden || fake.callCount("rollback") != 0 {
		t.Fatalf("wrong rollback token was accepted: status=%d", status)
	}
}

func TestAdapterErrorTriggersAutomaticRollback(t *testing.T) {
	fake := newFakeAdapter()
	fake.fail["snapshot_current"] = true
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "failed" || fake.callCount("rollback") != 1 {
		t.Fatalf("adapter error did not auto-rollback: status=%d change=%+v", status, cs)
	}
}

func TestArtifactEvidenceMismatchCannotAwaitConfirmation(t *testing.T) {
	fake := newFakeAdapter()
	fake.wrongApplyArtifactEvidence = true
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "failed" || fake.callCount("rollback") != 1 {
		t.Fatalf("foreign artifact evidence reached an applied state: status=%d change=%+v", status, cs)
	}
	if cs.ManagementVerified || cs.DataPlaneVerified || fake.callCount("verify_management_path") != 0 {
		t.Fatalf("verification continued after artifact binding mismatch: %+v", cs)
	}
}

func TestVerificationFailureRollsBackAndPersistsAcrossRestart(t *testing.T) {
	cfg := testAPIConfig(t)
	fake := newFakeAdapter()
	fake.fail["verify_data_plane"] = true
	srv, ts, client, csrf, authStore := newTransactionHTTP(t, cfg, fake)
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "rolled_back" || fake.callCount("rollback") != 1 {
		t.Fatalf("verification failure did not rollback: status=%d change=%+v", status, cs)
	}
	ts.Close()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	srv2, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close()
	if got := srv2.changes[cs.ID].State; got != "rolled_back" {
		t.Fatalf("rollback state did not survive restart: %s", got)
	}
	if srv2.configVersion != 1 || srv2.currentConfig().Services["github"].Category != "DIRECT_PREFERRED" {
		t.Fatal("failed candidate replaced the old active config")
	}
}

func TestCommitErrorTriggersRollback(t *testing.T) {
	fake := newFakeAdapter()
	fake.fail["commit"] = true
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, _ = postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "confirm", `{}`)
	if status != http.StatusOK || cs.State != "failed" || fake.callCount("commit") != 1 || fake.callCount("rollback") != 1 {
		t.Fatalf("commit failure did not rollback: status=%d change=%+v", status, cs)
	}
}

func TestConfirmRejectsAdapterArtifactMismatch(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, _ = postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if cs.State != "awaiting_confirmation" {
		t.Fatalf("test precondition failed: %+v", cs)
	}
	fake.mu.Lock()
	fake.activeArtifactManifestHash = "sha256:foreign-artifact-manifest"
	fake.mu.Unlock()
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "confirm", `{}`)
	if status != http.StatusOK || cs.State != "failed" || fake.callCount("commit") != 0 || fake.callCount("rollback") != 1 {
		t.Fatalf("confirm accepted adapter artifact mismatch: status=%d change=%+v", status, cs)
	}
}

func TestRollbackErrorProducesRollbackFailed(t *testing.T) {
	fake := newFakeAdapter()
	fake.fail["verify_data_plane"] = true
	fake.fail["rollback"] = true
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	_, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusInternalServerError {
		t.Fatalf("expected rollback failure 500, got %d", status)
	}
	if got := srv.changes[cs.ID].State; got != "rollback_failed" {
		t.Fatalf("expected rollback_failed, got %s", got)
	}
}

func TestExpiredTransactionAutomaticallyRollsBack(t *testing.T) {
	cfg := testAPIConfig(t)
	cfg.OpenWrt.RollbackTimeoutSeconds = 1
	fake := newFakeAdapter()
	srv, ts, client, csrf, _ := newTransactionHTTP(t, cfg, fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, _ = postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		stateName := srv.changes[cs.ID].State
		srv.mu.Unlock()
		if stateName == "expired" {
			if fake.callCount("rollback") != 1 {
				t.Fatal("expiry did not call rollback")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("transaction did not expire: %+v", srv.changes[cs.ID])
}

func TestHeadlessApplyRequiresProofExtendsRollbackAndConfirmsExplicitly(t *testing.T) {
	cfg := testAPIConfig(t)
	fake := newFakeAdapter()
	srv, ts, client, csrf, manager := newManagementProofTransactionHTTP(t, cfg, fake)
	defer srv.Close()
	defer ts.Close()

	missing := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	_, status := postAction(t, client, csrf, ts.URL, missing.ID, "apply", `{"management_mode":"headless"}`)
	if status != http.StatusConflict || fake.callCount("apply_candidate") != 0 {
		t.Fatalf("headless apply without proof was accepted: status=%d", status)
	}

	change := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	if _, err := manager.Issue(context.Background(), managementproof.Binding{TransactionID: change.TransactionID, RevisionID: change.RevisionID}, managementproof.Observation{
		Mode: managementproof.ModeHeadless, ClientIP: netip.MustParseAddr("127.0.0.2"), LocalIP: netip.MustParseAddr("127.0.0.1"),
		Interface: "lo", Subnet: netip.MustParsePrefix("127.0.0.0/8"), ControlPlaneURL: "http://127.0.0.1:8787/api/v1/health",
	}, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	change, status = postAction(t, client, csrf, ts.URL, change.ID, "apply", `{"management_mode":"headless"}`)
	if status != http.StatusOK || change.State != "awaiting_confirmation" {
		t.Fatalf("proved headless apply failed: status=%d change=%+v", status, change)
	}
	expires, err := time.Parse(time.RFC3339, change.ExpiresAt)
	if err != nil || time.Until(expires) < 9*time.Minute {
		t.Fatalf("headless rollback window was not extended: expires=%s err=%v", change.ExpiresAt, err)
	}
	_, status = postAction(t, client, csrf, ts.URL, change.ID, "confirm", `{}`)
	if status != http.StatusConflict || fake.callCount("commit") != 0 {
		t.Fatalf("implicit headless confirmation was accepted: status=%d", status)
	}
	change, status = postAction(t, client, csrf, ts.URL, change.ID, "confirm", `{"management_mode":"headless"}`)
	if status != http.StatusOK || change.State != "committed" || fake.callCount("commit") != 1 {
		t.Fatalf("explicit headless confirmation failed: status=%d change=%+v", status, change)
	}
}

func TestExpiryAndManualRollbackCallAdapterOnce(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, _ = postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if cs.State != "awaiting_confirmation" {
		t.Fatalf("test precondition failed: %+v", cs)
	}
	expiring := cs
	expiring.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	srv.scheduleExpiry(expiring)
	_, status := postAction(t, client, csrf, ts.URL, cs.ID, "rollback", `{}`)
	if status != http.StatusOK {
		t.Fatalf("manual rollback racing expiry returned %d", status)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if fake.callCount("rollback") == 1 {
			time.Sleep(20 * time.Millisecond)
			if fake.callCount("rollback") != 1 {
				t.Fatal("expiry and manual rollback both reached the adapter")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("neither expiry nor manual rollback reached the adapter")
}

func TestServerCloseWaitsForExpiryCallbackBeforeClosingState(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		fake := newFakeAdapter()
		srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
		cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
		cs, _ = postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
		if cs.State != "awaiting_confirmation" {
			ts.Close()
			_ = srv.Close()
			t.Fatalf("test precondition failed: %+v", cs)
		}
		expiring := cs
		expiring.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
		srv.scheduleExpiry(expiring)
		ts.Close()
		done := make(chan error, 1)
		go func() { done <- srv.Close() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("server close deadlocked with an expiry callback")
		}
	}
}

func TestRestartRecoversAwaitingConfirmation(t *testing.T) {
	cfg := testAPIConfig(t)
	fake := newFakeAdapter()
	srv, ts, client, csrf, authStore := newTransactionHTTP(t, cfg, fake)
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, _ = postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	ts.Close()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	srv2, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close()
	if got := srv2.changes[cs.ID].State; got != "awaiting_confirmation" {
		t.Fatalf("restart did not recover verified pending transaction: %s", got)
	}
}

func TestRecoveryFailClosedBetweenStateMachineSteps(t *testing.T) {
	cases := []struct {
		name  string
		state string
		steps []string
	}{
		{name: "after_prepare", state: "prepared", steps: []string{"prepare"}},
		{name: "after_validate_candidate", state: "prepared", steps: []string{"prepare", "validate_candidate"}},
		{name: "after_snapshot", state: "prepared", steps: []string{"prepare", "validate_candidate", "snapshot_current"}},
		{name: "after_apply", state: "applying", steps: []string{"prepare", "validate_candidate", "snapshot_current", "apply_candidate"}},
		{name: "after_management_verify", state: "verifying", steps: []string{"prepare", "validate_candidate", "snapshot_current", "apply_candidate", "verify_management_path"}},
		{name: "before_commit", state: "committing", steps: []string{"prepare", "validate_candidate", "snapshot_current", "apply_candidate", "verify_management_path", "verify_data_plane"}},
		{name: "during_rollback", state: "rolling_back", steps: []string{"prepare", "rollback"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testAPIConfig(t)
			fake := newFakeAdapter()
			srv, ts, client, csrf, authStore := newTransactionHTTP(t, cfg, fake)
			cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
			cs.State = tc.state
			for _, step := range tc.steps {
				cs.Steps = append(cs.Steps, adapter.StepResult{Step: step, Status: "OK", OK: true})
			}
			if err := srv.persistChangeSet(cs); err != nil {
				t.Fatal(err)
			}
			fake.activeRevision = cs.RevisionID
			fake.activeTransaction = cs.TransactionID
			ts.Close()
			if err := srv.Close(); err != nil {
				t.Fatal(err)
			}
			srv2, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
			if err != nil {
				t.Fatal(err)
			}
			defer srv2.Close()
			if got := srv2.changes[cs.ID].State; got != "rolled_back" {
				t.Fatalf("interrupted %s did not fail closed: %s", tc.name, got)
			}
		})
	}
}

func TestRecoveryFinalizesAdapterCommittedTransaction(t *testing.T) {
	cfg := testAPIConfig(t)
	fake := newFakeAdapter()
	srv, ts, client, csrf, authStore := newTransactionHTTP(t, cfg, fake)
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, _ = postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	cs.State = "committing"
	if err := srv.persistChangeSet(cs); err != nil {
		t.Fatal(err)
	}
	fake.transactionState = "committed"
	ts.Close()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	srv2, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close()
	if got := srv2.changes[cs.ID].State; got != "committed" {
		t.Fatalf("adapter-committed transaction was not finalized: %s", got)
	}
	if fake.callCount("rollback") != 0 || srv2.configVersion != 2 {
		t.Fatal("committed transaction was rolled back during recovery")
	}
}

func TestParallelApplyOnlyOneSucceeds(t *testing.T) {
	fake := newFakeAdapter()
	fake.applyStarted = make(chan struct{}, 1)
	fake.applyRelease = make(chan struct{})
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	first := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	second := createValidatedChange(t, client, csrf, ts.URL, "DIRECT_ONLY")
	result := make(chan int, 1)
	go func() {
		_, status := postActionNoTest(client, csrf, ts.URL, first.ID, "apply", `{}`)
		result <- status
	}()
	select {
	case <-fake.applyStarted:
	case <-time.After(time.Second):
		t.Fatal("first apply did not start")
	}
	secondResult := make(chan int, 1)
	go func() {
		_, status := postActionNoTest(client, csrf, ts.URL, second.ID, "apply", `{}`)
		secondResult <- status
	}()
	close(fake.applyRelease)
	if status := <-result; status != http.StatusOK {
		t.Fatalf("first apply status %d", status)
	}
	if status := <-secondResult; status != http.StatusConflict {
		t.Fatalf("parallel apply status %d", status)
	}
}

func TestStaleChangeSetVersionReturns409(t *testing.T) {
	fake := newFakeAdapter()
	srv, ts, client, csrf, _ := newTransactionHTTP(t, testAPIConfig(t), fake)
	defer srv.Close()
	defer ts.Close()
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	_, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{"version":1}`)
	if status != http.StatusConflict {
		t.Fatalf("stale ChangeSet version returned %d", status)
	}
}

func TestRestartRetriesBusyCommittedDataplaneReconcile(t *testing.T) {
	cfg := testAPIConfig(t)
	fake := newFakeAdapter()
	srv, ts, client, csrf, authStore := newTransactionHTTP(t, cfg, fake)
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "awaiting_confirmation" {
		t.Fatalf("apply status=%d change=%+v", status, cs)
	}
	cs, status = postAction(t, client, csrf, ts.URL, cs.ID, "confirm", `{}`)
	if status != http.StatusOK || cs.State != "committed" {
		t.Fatalf("confirm status=%d change=%+v", status, cs)
	}
	ts.Close()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if got := fake.callCount("reconcile"); got != 0 {
		t.Fatalf("reconcile ran before restart: %d", got)
	}
	fake.mu.Lock()
	fake.reconcileBusyCount = 1
	fake.mu.Unlock()

	srv2, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close()
	if got := fake.callCount("reconcile"); got != 2 {
		t.Fatalf("busy committed dataplane reconcile was not retried exactly once: %d", got)
	}
	if recovery := srv2.currentRecoveryStatus(); recovery.Status != "ok" {
		t.Fatalf("transient adapter contention left recovery degraded: %+v", recovery)
	}
}

func TestRestartReconcilesCommittedDataplaneAfterStateRootMigration(t *testing.T) {
	cfg := testAPIConfig(t)
	fake := newFakeAdapter()
	srv, ts, client, csrf, authStore := newTransactionHTTP(t, cfg, fake)
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "awaiting_confirmation" {
		t.Fatalf("apply status=%d change=%+v", status, cs)
	}
	cs, status = postAction(t, client, csrf, ts.URL, cs.ID, "confirm", `{}`)
	if status != http.StatusOK || cs.State != "committed" {
		t.Fatalf("confirm status=%d change=%+v", status, cs)
	}
	ts.Close()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}

	oldStateDir := cfg.Storage.StateDir
	newStateDir := oldStateDir + "-migrated"
	if err := os.Rename(oldStateDir, newStateDir); err != nil {
		t.Fatal(err)
	}
	cfg.Storage.StateDir = newStateDir
	cfg.Storage.RuntimeDir = newStateDir
	cfg.Storage.Database = filepath.Join(newStateDir, "router-policy.bbolt")

	srv2, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close()
	if got := fake.callCount("reconcile"); got != 1 {
		t.Fatalf("migrated committed dataplane was not reconciled exactly once: %d", got)
	}
	if recovery := srv2.currentRecoveryStatus(); recovery.Status != "ok" {
		t.Fatalf("state-root migration left recovery degraded: %+v", recovery)
	}
}

func TestRestartKeepsManagementAvailableWhenCommittedReconcileFails(t *testing.T) {
	cfg := testAPIConfig(t)
	fake := newFakeAdapter()
	srv, ts, client, csrf, authStore := newTransactionHTTP(t, cfg, fake)
	cs := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	cs, status := postAction(t, client, csrf, ts.URL, cs.ID, "apply", `{}`)
	if status != http.StatusOK || cs.State != "awaiting_confirmation" {
		t.Fatalf("apply status=%d change=%+v", status, cs)
	}
	cs, status = postAction(t, client, csrf, ts.URL, cs.ID, "confirm", `{}`)
	if status != http.StatusOK || cs.State != "committed" {
		t.Fatalf("confirm status=%d change=%+v", status, cs)
	}
	ts.Close()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	fake.fail["reconcile"] = true

	srv2, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: fake, Development: true})
	if err != nil {
		t.Fatalf("management server must remain available after recovery failure: %v", err)
	}
	defer srv2.Close()
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()
	resp, err := http.Get(ts2.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env.Data)
	var health struct {
		Status         string `json:"status"`
		RecoveryStatus string `json:"recovery_status"`
	}
	if err := json.Unmarshal(raw, &health); err != nil {
		t.Fatal(err)
	}
	if health.Status != "degraded" || health.RecoveryStatus != "error" {
		t.Fatalf("recovery failure was hidden from health endpoint: %+v", health)
	}
}

type blockingRecoveryAdapter struct {
	*fakeAdapter
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (a *blockingRecoveryAdapter) Reconcile(ctx context.Context, target adapter.RecoveryTarget) adapter.StepResult {
	a.once.Do(func() { close(a.started) })
	select {
	case <-ctx.Done():
		now := time.Now().UTC()
		return adapter.StepResult{Step: "reconcile", Status: "ERROR", Reason: ctx.Err().Error(), StartedAt: now, FinishedAt: now}
	case <-a.release:
		return a.fakeAdapter.Reconcile(ctx, target)
	}
}

func TestDeferredRecoveryKeepsHealthEndpointAvailableDuringReconcile(t *testing.T) {
	cfg := testAPIConfig(t)
	fake := newFakeAdapter()
	srv, ts, client, csrf, authStore := newTransactionHTTP(t, cfg, fake)
	change := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	change, status := postAction(t, client, csrf, ts.URL, change.ID, "apply", `{}`)
	if status != http.StatusOK || change.State != "awaiting_confirmation" {
		t.Fatalf("apply status=%d change=%+v", status, change)
	}
	change, status = postAction(t, client, csrf, ts.URL, change.ID, "confirm", `{}`)
	if status != http.StatusOK || change.State != "committed" {
		t.Fatalf("confirm status=%d change=%+v", status, change)
	}
	ts.Close()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}

	blocking := &blockingRecoveryAdapter{fakeAdapter: fake, started: make(chan struct{}), release: make(chan struct{})}
	restarted, err := NewServerWithOptions(cfg, Options{
		Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: blocking,
		Development: true, DeferRecovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if recovery := restarted.currentRecoveryStatus(); recovery.Status != "starting" || recovery.RevisionID != change.RevisionID {
		t.Fatalf("deferred recovery did not expose startup state: %+v", recovery)
	}
	httpServer := httptest.NewServer(restarted.Handler())
	defer httpServer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	restarted.StartScheduler(ctx)
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("deferred reconcile did not start")
	}
	response, err := http.Get(httpServer.URL + "/api/v1/health")
	if err != nil {
		t.Fatalf("health endpoint was blocked by recovery: %v", err)
	}
	var env Envelope
	if err := json.NewDecoder(response.Body).Decode(&env); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	raw, _ := json.Marshal(env.Data)
	var health struct {
		Status         string `json:"status"`
		RecoveryStatus string `json:"recovery_status"`
		ActiveRevision string `json:"active_revision"`
	}
	if err := json.Unmarshal(raw, &health); err != nil {
		t.Fatal(err)
	}
	if health.Status != "starting" || health.RecoveryStatus != "starting" || health.ActiveRevision != change.RevisionID {
		t.Fatalf("health concealed deferred recovery: %+v", health)
	}
	close(blocking.release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && restarted.currentRecoveryStatus().Status == "starting" {
		time.Sleep(10 * time.Millisecond)
	}
	if recovery := restarted.currentRecoveryStatus(); recovery.Status != "ok" {
		t.Fatalf("deferred recovery did not complete: %+v", recovery)
	}
}

func newTransactionHTTP(t *testing.T, cfg *config.Config, productionAdapter adapter.Interface) (*Server, *httptest.Server, *http.Client, string, *auth.Store) {
	return newTransactionHTTPMode(t, cfg, productionAdapter, true)
}

func TestIdenticalApplyIsNoopWithoutNewDeploymentWork(t *testing.T) {
	cfg := testAPIConfig(t)
	fake := newFakeAdapter()
	srv, ts, client, csrf, _ := newTransactionHTTP(t, cfg, fake)
	defer srv.Close()
	defer ts.Close()

	first := createValidatedChange(t, client, csrf, ts.URL, "GEO_LOCKED")
	first, status := postAction(t, client, csrf, ts.URL, first.ID, "apply", `{}`)
	if status != http.StatusOK || first.State != "awaiting_confirmation" {
		t.Fatalf("first apply failed: status=%d change=%+v", status, first)
	}
	first, status = postAction(t, client, csrf, ts.URL, first.ID, "confirm", `{}`)
	if status != http.StatusOK || first.State != "committed" {
		t.Fatalf("first commit failed: status=%d change=%+v", status, first)
	}
	response, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var healthEnvelope Envelope
	if err := json.NewDecoder(response.Body).Decode(&healthEnvelope); err != nil {
		t.Fatal(err)
	}
	healthRaw, _ := json.Marshal(healthEnvelope.Data)
	var health struct {
		ActiveRevision string `json:"active_revision"`
	}
	if err := json.Unmarshal(healthRaw, &health); err != nil {
		t.Fatal(err)
	}
	if health.ActiveRevision != first.RevisionID {
		t.Fatalf("health exposed stale revision after commit: got=%s want=%s", health.ActiveRevision, first.RevisionID)
	}

	beforePrepare := fake.callCount("prepare")
	beforeApply := fake.callCount("apply_candidate")
	beforeCommit := fake.callCount("commit")
	change, err := srv.createDraftChange("No-op apply", "same config", first.CandidateVersion, []ChangeOp{{Type: "set", Path: "/services/github/category", Value: "GEO_LOCKED"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	change, failure := srv.validateChangeSet(change)
	if failure != nil || !change.Noop || change.State != "validated" || change.RevisionID != first.RevisionID {
		t.Fatalf("identical config was not recognized as no-op: change=%+v failure=%+v", change, failure)
	}
	change, failure = srv.applyChangeSet(context.Background(), change)
	if failure != nil || !change.Noop || change.State != "committed" || change.AdapterStatus != "NOOP" {
		t.Fatalf("no-op apply failed: change=%+v failure=%+v", change, failure)
	}
	if fake.callCount("prepare") != beforePrepare || fake.callCount("apply_candidate") != beforeApply || fake.callCount("commit") != beforeCommit {
		t.Fatalf("no-op invoked deployment steps: calls=%v", fake.calls)
	}
}

func newTransactionHTTPMode(t *testing.T, cfg *config.Config, productionAdapter adapter.Interface, development bool) (*Server, *httptest.Server, *http.Client, string, *auth.Store) {
	var provider platform.Provider = platform.NewOpenWrtProvider()
	if development {
		provider = platform.DevelopmentMockProvider{}
	}
	return newTransactionHTTPWithProvider(t, cfg, productionAdapter, development, provider)
}

func newTransactionHTTPWithProvider(t *testing.T, cfg *config.Config, productionAdapter adapter.Interface, development bool, provider platform.Provider) (*Server, *httptest.Server, *http.Client, string, *auth.Store) {
	t.Helper()
	authStore, err := auth.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := authStore.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authStore.SetupAdmin("admin", "CorrectHorse123!", token); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: provider, ProductionAdapter: productionAdapter, Development: development})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	client, csrf := login(t, ts.URL)
	return srv, ts, client, csrf, authStore
}

func newManagementProofTransactionHTTP(t *testing.T, cfg *config.Config, productionAdapter adapter.Interface) (*Server, *httptest.Server, *http.Client, string, *managementproof.Manager) {
	t.Helper()
	authStore, err := auth.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := authStore.CreateSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authStore.SetupAdmin("admin", "CorrectHorse123!", token); err != nil {
		t.Fatal(err)
	}
	bootIDPath := filepath.Join(cfg.Storage.StateDir, "test-boot-id")
	if err := os.WriteFile(bootIDPath, []byte("boot-api-proof-001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := managementproof.New(cfg.Storage.StateDir, cfg.Storage.RuntimeDir, managementproof.Options{BootIDPath: bootIDPath, AdminProbe: func(context.Context, string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServerWithOptions(cfg, Options{Auth: authStore, Provider: platform.DevelopmentMockProvider{}, ProductionAdapter: productionAdapter, Development: true, ManagementProofs: manager, RequireManagementProof: true})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	client, csrf := login(t, ts.URL)
	return srv, ts, client, csrf, manager
}

func testArtifactNetworkDiagnostics(simulation bool) platform.NetworkDiagnostics {
	now := time.Now().UTC()
	return platform.NetworkDiagnostics{
		Status:               "VERIFIED",
		Source:               "hardware-test-provider",
		Simulation:           simulation,
		WANInterface:         "eth1",
		LANInterfaces:        []string{"br-lan"},
		IPv4Gateway:          "192.0.2.1",
		IPv6Gateway:          "2001:db8::1",
		IPv6Available:        true,
		DNSResolvers:         []string{"192.0.2.53"},
		TransparentProxyMode: "tproxy",
		FlowOffloadingStatus: "VERIFIED",
		SoftwareFlowOffload:  false,
		HardwareFlowOffload:  false,
		CollectedAt:          now,
		ExpiresAt:            now.Add(time.Minute),
	}
}

func createValidatedChange(t *testing.T, client *http.Client, csrf, baseURL, category string) ChangeSet {
	t.Helper()
	allowed := []string{"direct", "smart_dns", "drop"}
	requireNonRU := false
	if category == "GEO_LOCKED" {
		allowed = []string{"smart_dns", "drop"}
		requireNonRU = true
	} else if category == "DIRECT_ONLY" {
		allowed = []string{"direct"}
	}
	allowedJSON, err := json.Marshal(allowed)
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"title":"Change %s","base_version":1,"operations":[{"type":"set","path":"/services/github/category","value":%q},{"type":"set","path":"/services/github/allowed_paths","value":%s},{"type":"set","path":"/services/github/require_non_ru_egress","value":%t}]}`, category, category, allowedJSON, requireNonRU)
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/changes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status %d", resp.StatusCode)
	}
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env.Data)
	var cs ChangeSet
	if err := json.Unmarshal(raw, &cs); err != nil {
		t.Fatal(err)
	}
	cs, status := postAction(t, client, csrf, baseURL, cs.ID, "validate", `{}`)
	if status != http.StatusOK || cs.State != "validated" {
		t.Fatalf("validate status=%d change=%+v", status, cs)
	}
	return cs
}

func postAction(t *testing.T, client *http.Client, csrf, baseURL, id, action, body string) (ChangeSet, int) {
	t.Helper()
	cs, status := postActionNoTest(client, csrf, baseURL, id, action, body)
	return cs, status
}

func postActionNoTest(client *http.Client, csrf, baseURL, id, action, body string) (ChangeSet, int) {
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/changes/"+id+"/"+action, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		return ChangeSet{}, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return ChangeSet{Validation: []Validation{{Level: "error", Code: "http_error", Message: string(raw)}}}, resp.StatusCode
	}
	var env Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return ChangeSet{}, resp.StatusCode
	}
	raw, _ := json.Marshal(env.Data)
	var cs ChangeSet
	_ = json.Unmarshal(raw, &cs)
	return cs, resp.StatusCode
}
