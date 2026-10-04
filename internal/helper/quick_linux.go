//go:build linux

package helper

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"router-policy/internal/config"
)

func (e AdapterExecutor) executeZapretQuick(ctx context.Context, request Request) Response {
	response := ResponseFrom(request, false, "zapret_quick_failed", "")
	response.Operation = "quick_check"
	response.SemanticState = "failed"
	bootstrap, err := config.Load(e.ConfigPath)
	if err != nil {
		response.Error = "quick test bootstrap unavailable"
		return response
	}
	binding, err := CalibrationBinding(bootstrap.Storage.StateDir, bootstrap.Storage.RuntimeDir)
	if err != nil || !quickBindingMatches(binding, request) {
		response.ErrorCode = "zapret_quick_binding_mismatch"
		response.Error = "quick test active binding mismatch"
		return response
	}
	q := request.ZapretQuick
	catalog := "/etc/router-policy/zapret/catalog.json"
	if info, statErr := os.Lstat(catalog); statErr == nil {
		owner, ok := info.Sys().(*syscall.Stat_t)
		var marker struct {
			Owner string `json:"owner"`
		}
		var raw []byte
		if info.Mode().IsRegular() && info.Size() <= 256<<10 {
			raw, _ = os.ReadFile(catalog)
		}
		if !ok || owner.Uid != 0 || info.Mode().Perm()&0o022 != 0 || json.Unmarshal(raw, &marker) != nil || marker.Owner != "flintroute" {
			response.ErrorCode = "zapret_catalog_foreign"
			response.Error = "existing quick catalog has no verified ownership"
			return response
		}
	} else if !os.IsNotExist(statErr) {
		response.Error = "quick catalog could not be inspected"
		return response
	}
	args := []string{"--apply", "--mode", "quick", "--domain", q.Domain, "--bundle-id", q.BundleID, "--network-fingerprint", q.NetworkFingerprint}
	command := exec.Command("/usr/lib/router-policy/scripts/quick-zapret-check.sh", args...)
	for _, path := range []string{command.Path, "/usr/bin/router-policy", "/usr/bin/nfqws"} {
		info, statErr := os.Lstat(path)
		owner, ownerOK := any(nil), false
		if statErr == nil {
			owner = info.Sys()
			_, ownerOK = owner.(*syscall.Stat_t)
		}
		if statErr != nil || !info.Mode().IsRegular() || !ownerOK || owner.(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			response.Error = "quick test executable is not a trusted root-owned file"
			return response
		}
	}
	validation, err := runFixedProbeCommand(ctx, "/usr/bin/router-policy", "internal-validate-zapret-quick", request.RevisionID, request.TransactionID, request.CandidateHash, request.ArtifactManifestHash, request.RollbackTokenHash)
	var checked struct {
		RevisionID    string `json:"revision_id"`
		TransactionID string `json:"transaction_id"`
		CandidateHash string `json:"candidate_hash"`
		ArtifactHash  string `json:"artifact_manifest_hash"`
		TokenHash     string `json:"rollback_token_hash"`
		Validated     bool   `json:"validated"`
		Queue         int    `json:"queue"`
	}
	if err != nil || json.Unmarshal(validation, &checked) != nil || !checked.Validated || checked.RevisionID != request.RevisionID || checked.TransactionID != request.TransactionID || checked.CandidateHash != request.CandidateHash || checked.ArtifactHash != request.ArtifactManifestHash || checked.TokenHash != request.RollbackTokenHash || checked.Queue < 1 || checked.Queue > 65535 {
		response.Error = "quick test committed artifact validation failed"
		return response
	}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp", "ROUTER_POLICY_CONFIG=" + e.ConfigPath, "NFQWS_BIN=/usr/bin/nfqws", "ROUTER_POLICY_BIN=/usr/bin/router-policy", "ROUTER_POLICY_RUNTIME_DIR=/tmp/router-policy", "ZAPRET_CATALOG_OUT=/etc/router-policy/zapret/catalog.json", "ZAPRET_MANAGED_QUEUE=" + strconv.Itoa(checked.Queue), "ZAPRET_CALIBRATION_IPV4=" + strings.Join(q.ResolvedIPv4, ",")}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr boundedProbeOutput
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err = command.Start(); err != nil {
		response.Error = "quick test runner could not start"
		return response
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		}
		err = ctx.Err()
	}
	if err != nil || stdout.exceeded || stderr.exceeded || stdout.Len() > 1<<20 {
		response.Error = "quick test runner failed or exceeded its bounded output"
		response.Evidence = map[string]string{"diagnostic": boundedQuickDiagnostic(stderr.String())}
		return response
	}
	// The controller performs the full attempt-level semantic validation.
	// The executor additionally rejects non-JSON and a changed active generation.
	if !json.Valid(stdout.Bytes()) {
		response.Error = "quick test returned malformed JSON"
		return response
	}
	// Catalogs contain reviewed strategy arguments, not subscription secrets.
	// Keep the exact owned result readable by the non-root controller.
	info, statErr := os.Lstat(catalog)
	if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || os.Chown(catalog, 0, 1) != nil || os.Chmod(catalog, 0o640) != nil {
		response.Error = "quick test catalog publication failed"
		return response
	}
	after, err := CalibrationBinding(bootstrap.Storage.StateDir, bootstrap.Storage.RuntimeDir)
	if err != nil || !quickBindingMatches(after, request) {
		response.ErrorCode = "zapret_quick_binding_changed"
		response.Error = "active generation changed during quick test"
		return response
	}
	response.Accepted = true
	response.State = "accepted"
	response.SemanticState = "completed"
	response.ErrorCode = ""
	response.Evidence = map[string]string{"payload": stdout.String()}
	return response
}

func quickBindingMatches(a, b Request) bool {
	return a.RevisionID == b.RevisionID && a.TransactionID == b.TransactionID && a.CandidateHash == b.CandidateHash && a.ArtifactManifestHash == b.ArtifactManifestHash && a.RollbackTokenHash == b.RollbackTokenHash
}
func boundedQuickDiagnostic(value string) string {
	if len(value) > 1024 {
		value = value[len(value)-1024:]
	}
	return strings.Map(func(r rune) rune {
		if r < ' ' && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, value)
}
