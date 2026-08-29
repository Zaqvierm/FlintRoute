package component

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Driver interface {
	Platform(context.Context) (Platform, error)
	Inspect(context.Context, Kind) (Health, bool, string, error)
	Preflight(context.Context, Release, Asset) (Preflight, error)
	Install(context.Context, Release, Asset, string, Record) (Record, error)
	Restart(context.Context, Kind) error
	Rollback(context.Context, Record) (Record, error)
	Uninstall(context.Context, Kind, bool) error
	Health(context.Context, Kind) (Health, error)
}

type ReleaseSource interface {
	Latest(context.Context, Release) (string, error)
}

type Manager struct {
	StateDir   string
	RuntimeDir string
	Driver     Driver
	HTTP       *http.Client
	Releases   ReleaseSource
	Catalog    map[Kind]Release
	Now        func() time.Time
	// DirectMutationAllowed is an explicit development/test escape hatch.
	// Production managers must use a helper-backed executor instead of calling
	// an OpenWrtDriver directly from the controller process.  Keep the default
	// fail-closed so adding a new production wiring site cannot silently regain
	// root-owned file/service mutation.
	DirectMutationAllowed bool
	mu                    sync.Mutex
}

func (m *Manager) List(ctx context.Context) ([]Status, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	kinds := []Kind{KindZapret, KindXray, KindTGWS}
	statuses := make([]Status, 0, len(kinds))
	for _, kind := range kinds {
		status, err := m.Status(ctx, kind, false)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func (m *Manager) Status(ctx context.Context, kind Kind, checkUpstream bool) (Status, error) {
	if err := m.validate(); err != nil {
		return Status{}, err
	}
	release, ok := m.Catalog[kind]
	if !ok || !kind.Valid() {
		return Status{}, errors.New("unsupported component")
	}
	record, err := m.loadRecord(kind)
	if err != nil {
		return Status{}, err
	}
	health, present, detectedVersion, inspectErr := m.Driver.Inspect(ctx, kind)
	if inspectErr != nil {
		health = Health{State: "failed", ServiceState: "unknown", Reason: inspectErr.Error()}
	}
	status := statusFromRecord(record, release, health)
	status.Detected = present
	status.Managed = record.Installed
	switch {
	case record.Installed:
		status.Ownership = "flintroute"
	case present:
		// A system binary without a FlintRoute registry record is evidence of
		// an external/foreign installation, not permission to manage it. Do
		// not expose the driver's managed-service health as a PASS signal.
		status.Installed = true
		status.Version = detectedVersion
		status.Architecture = "detected"
		status.Ownership = "foreign"
		status.ServiceState = "foreign"
		status.HealthState = "foreign"
		status.HealthReady = false
		status.HealthReason = "Компонент обнаружен вне FlintRoute; ownership и dataplane не подтверждены"
	default:
		status.Ownership = "absent"
	}
	if checkUpstream && m.Releases != nil {
		latest, latestErr := m.Releases.Latest(ctx, release)
		if latestErr != nil {
			status.UpdateBlockedReason = latestErr.Error()
		} else {
			status.LatestUpstream = latest
			status.UpdateAvailable = record.Installed && record.Version != "" && record.Version != release.Version
			if latest != "" && latest != release.Version {
				status.UpdateBlockedReason = "upstream release is not in the vetted FlintRoute catalog yet"
			}
		}
	}
	return status, nil
}

func (m *Manager) Execute(ctx context.Context, request Request) (Result, error) {
	if !request.Kind.Valid() || !request.Action.Valid() {
		return Result{}, errors.New("unsupported component action")
	}
	if isMutationAction(request.Action) && !m.DirectMutationAllowed {
		return Result{}, errors.New("component mutation requires a helper-backed privileged executor")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.validate(); err != nil {
		return Result{}, err
	}
	release := m.Catalog[request.Kind]
	record, err := m.loadRecord(request.Kind)
	if err != nil {
		return Result{}, err
	}
	if !record.Installed && request.Action != ActionCheck && request.Action != ActionCheckUpdates {
		// Never let an install/update/uninstall-style operation overwrite a
		// binary that exists without a FlintRoute registry record. The UI also
		// hides mutation controls for this state, but the backend must enforce
		// the ownership fence for direct API callers and stale clients too.
		_, present, _, inspectErr := m.Driver.Inspect(ctx, request.Kind)
		if inspectErr != nil {
			return Result{}, fmt.Errorf("component ownership check failed: %w", inspectErr)
		}
		if present {
			return Result{}, errors.New("component resource is detected outside FlintRoute; ownership handoff is required before mutation")
		}
	}
	result := Result{Action: request.Action}
	switch request.Action {
	case ActionCheck:
		result.Stages = []string{"inspect", "health_check"}
	case ActionCheckUpdates:
		result.Status, err = m.Status(ctx, request.Kind, true)
		result.Stages = []string{"release_metadata", "compatibility_check"}
		return result, err
	case ActionInstall, ActionUpdate:
		result, err = m.install(ctx, request, release, record)
		if err != nil {
			return result, err
		}
	case ActionRestart:
		if !record.Installed {
			return result, errors.New("component is not managed by FlintRoute")
		}
		if err := m.Driver.Restart(ctx, request.Kind); err != nil {
			return result, fmt.Errorf("restart component: %w", err)
		}
		result.Changed = true
		result.Stages = []string{"restart", "health_check"}
	case ActionRollback:
		if record.RollbackVersion == "" || record.RollbackPath == "" {
			return result, errors.New("rollback version is unavailable")
		}
		record, err = m.Driver.Rollback(ctx, record)
		if err != nil {
			return result, fmt.Errorf("rollback component: %w", err)
		}
		if err := m.saveRecord(record); err != nil {
			return result, err
		}
		result.Changed = true
		result.Rollback = true
		result.Stages = []string{"restore_previous_version", "restart", "health_check"}
	case ActionUninstall:
		if !record.Installed {
			return result, errors.New("component is not managed by FlintRoute")
		}
		if !request.ConfirmDisruption {
			return result, errors.New("component uninstall requires explicit disruption confirmation")
		}
		if err := m.Driver.Uninstall(ctx, request.Kind, request.PreserveConfig); err != nil {
			return result, fmt.Errorf("uninstall component: %w", err)
		}
		if err := m.removeRecord(request.Kind); err != nil {
			return result, err
		}
		result.Changed = true
		result.Stages = []string{"dependency_check", "stop", "uninstall", "cleanup", "health_check"}
	}
	result.Status, err = m.Status(ctx, request.Kind, false)
	return result, err
}

func isMutationAction(action Action) bool {
	switch action {
	case ActionInstall, ActionUpdate, ActionRestart, ActionRollback, ActionUninstall:
		return true
	default:
		return false
	}
}

func (m *Manager) install(ctx context.Context, request Request, release Release, previous Record) (Result, error) {
	result := Result{Action: request.Action, Stages: []string{"preflight", "platform_detection", "release_selection"}}
	if previous.Installed && previous.Version == release.Version {
		health, present, detected, inspectErr := m.Driver.Inspect(ctx, request.Kind)
		intact := inspectErr == nil && present && detected != "" && health.Ready
		if request.Kind == KindTGWS && health.State == "needs_configuration" {
			intact = inspectErr == nil && present && detected != ""
		}
		if intact {
			result.Status, _ = m.Status(ctx, request.Kind, false)
			return result, nil
		}
	}
	platform, err := m.Driver.Platform(ctx)
	if err != nil {
		return result, fmt.Errorf("platform detection: %w", err)
	}
	asset, err := SelectAsset(release, platform)
	if err != nil {
		return result, err
	}
	preflight, err := m.Driver.Preflight(ctx, release, asset)
	if err != nil {
		return result, fmt.Errorf("component preflight: %w", err)
	}
	if !preflight.Ready {
		return result, fmt.Errorf("component preflight failed: %s", preflight.Reason)
	}
	result.Stages = append(result.Stages, "download", "checksum_verification")
	artifact, err := m.download(ctx, release, asset)
	if err != nil {
		return result, err
	}
	defer os.Remove(artifact)
	installed, err := m.Driver.Install(ctx, release, asset, artifact, previous)
	if err != nil {
		return result, fmt.Errorf("install component: %w", err)
	}
	result.Stages = append(result.Stages, "install", "service_setup", "health_check")
	health, healthErr := m.Driver.Health(ctx, request.Kind)
	configurationPending := request.Kind == KindTGWS && healthErr == nil && health.State == "needs_configuration"
	if healthErr != nil || (!health.Ready && !configurationPending) {
		if installed.RollbackVersion != "" && installed.RollbackPath != "" {
			if restored, rollbackErr := m.Driver.Rollback(ctx, installed); rollbackErr == nil {
				_ = m.saveRecord(restored)
				result.Rollback = true
			}
		}
		if healthErr != nil {
			return result, fmt.Errorf("component health check failed: %w", healthErr)
		}
		return result, fmt.Errorf("component health check failed: %s", health.Reason)
	}
	installed.LastCheckedAt = m.now()
	if err := m.saveRecord(installed); err != nil {
		return result, err
	}
	result.Changed = true
	result.Status = statusFromRecord(installed, release, health)
	if configurationPending {
		result.Stages = append(result.Stages, "configuration_required")
	}
	return result, nil
}

func (m *Manager) download(ctx context.Context, release Release, asset Asset) (string, error) {
	parsed, err := url.Parse(asset.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != githubAssetHost || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("component asset URL is not allowlisted")
	}
	if !strings.Contains(parsed.Path, "/releases/download/"+release.Version+"/") {
		return "", errors.New("component asset URL is not bound to the supported release")
	}
	if asset.Size <= 0 || asset.Size > 128<<20 || len(asset.SHA256) != 64 {
		return "", errors.New("component asset metadata is invalid")
	}
	if err := os.MkdirAll(filepath.Join(m.RuntimeDir, "components"), 0o700); err != nil {
		return "", err
	}
	pattern := string(release.Kind) + "-*"
	if asset.PackageType == "ipk" {
		// opkg rejects verified local packages whose temporary filename has no
		// .ipk suffix, even when the archive contents are otherwise valid.
		pattern += ".ipk"
	}
	file, err := os.CreateTemp(filepath.Join(m.RuntimeDir, "components"), pattern)
	if err != nil {
		return "", err
	}
	path := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return "", err
	}
	client := m.httpClient()
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return "", errors.New("component download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > asset.Size {
		return "", fmt.Errorf("component download returned HTTP %d", response.StatusCode)
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, asset.Size+1))
	if err != nil || written != asset.Size {
		return "", errors.New("component download size mismatch")
	}
	if hex.EncodeToString(hash.Sum(nil)) != asset.SHA256 {
		return "", errors.New("component checksum mismatch")
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

func (m *Manager) validate() error {
	if m == nil || m.Driver == nil || !filepath.IsAbs(m.StateDir) || !filepath.IsAbs(m.RuntimeDir) {
		return errors.New("component manager is not configured")
	}
	if m.Catalog == nil {
		m.Catalog = SupportedCatalog()
	}
	if m.Now == nil {
		m.Now = func() time.Time { return time.Now().UTC() }
	}
	return nil
}

func (m *Manager) now() time.Time { return m.Now().UTC() }

func (m *Manager) httpClient() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" || (req.URL.Host != githubAssetHost && req.URL.Host != "release-assets.githubusercontent.com") {
			return errors.New("component download redirect refused")
		}
		return nil
	}}
}

func (m *Manager) recordPath(kind Kind) string {
	return filepath.Join(m.StateDir, "components", string(kind)+".json")
}

func (m *Manager) loadRecord(kind Kind) (Record, error) {
	raw, err := os.ReadFile(m.recordPath(kind))
	if errors.Is(err, os.ErrNotExist) {
		return Record{Kind: kind}, nil
	}
	if err != nil {
		return Record{}, err
	}
	var record Record
	if err := json.Unmarshal(raw, &record); err != nil || record.Kind != kind {
		return Record{}, errors.New("component registry record is invalid")
	}
	return record, nil
}

func (m *Manager) saveRecord(record Record) error {
	dir := filepath.Join(m.StateDir, "components")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp, err := os.CreateTemp(dir, ".registry-*")
	if err != nil {
		return err
	}
	path := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(path, m.recordPath(record.Kind)); err != nil {
		return err
	}
	ok = true
	return nil
}

func (m *Manager) removeRecord(kind Kind) error {
	err := os.Remove(m.recordPath(kind))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func statusFromRecord(record Record, release Release, health Health) Status {
	checksum := canonicalDigest(record.Checksum)
	binaryChecksum := canonicalDigest(record.BinaryChecksum)
	asset, hasAsset := pinnedAsset(record, release)
	// A component discovered on the host has no registry record yet.  If its
	// detected version matches the vetted release, expose the catalog digest as
	// the expected setup pin.  The setup checker still hashes the actual binary
	// and rejects a mismatch; this is metadata for preflight, not proof that the
	// file is trusted.
	if checksum == "" && sameReleaseVersion(record.Version, release.Version) {
		if hasAsset {
			checksum = canonicalDigest(asset.SHA256)
		}
	}
	if binaryChecksum == "" && sameReleaseVersion(record.Version, release.Version) && hasAsset {
		binaryChecksum = canonicalDigest(asset.BinarySHA256)
	}
	status := Status{
		Kind: record.Kind, Installed: record.Installed, Version: record.Version, LatestSupported: release.Version,
		Architecture: record.Architecture, Source: release.Source, PinnedAssetURL: pinnedAssetURL(record, release), Checksum: checksum, BinaryChecksum: binaryChecksum,
		ServiceState: health.ServiceState, HealthState: health.State, HealthReady: health.Ready,
		HealthReason: health.Reason, LastSuccessfulCheck: health.LastSuccessful, LastCheckedAt: record.LastCheckedAt,
		RollbackVersion: record.RollbackVersion,
	}
	switch record.Kind {
	case KindXray:
		status.NextActions = []string{"add_subscription", "add_manual_server"}
	case KindZapret:
		status.NextActions = []string{"run_calibration"}
	case KindTGWS:
		status.NextActions = []string{"configure_proxy", "verify_telegram_transport"}
	}
	return status
}

func pinnedAssetURL(record Record, release Release) string {
	asset, ok := pinnedAsset(record, release)
	if ok {
		return asset.URL
	}
	return ""
}

func pinnedAsset(record Record, release Release) (Asset, bool) {
	for _, asset := range release.Assets {
		if record.Architecture != "" && asset.Architecture == record.Architecture {
			return asset, true
		}
	}
	if len(release.Assets) == 1 {
		return release.Assets[0], true
	}
	return Asset{}, false
}

func sameReleaseVersion(left, right string) bool {
	left = strings.TrimPrefix(strings.TrimSpace(left), "v")
	right = strings.TrimPrefix(strings.TrimSpace(right), "v")
	return left != "" && left == right
}

func canonicalDigest(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(value, "sha256:") {
		return value
	}
	if len(value) == sha256.Size*2 {
		if _, err := hex.DecodeString(value); err == nil {
			return "sha256:" + value
		}
	}
	return value
}

type GitHubReleaseSource struct{ Client *http.Client }

func (s GitHubReleaseSource) Latest(ctx context.Context, release Release) (string, error) {
	parsed, err := url.Parse(release.ReleaseAPI)
	if err != nil || parsed.Scheme != "https" || parsed.Host != githubReleaseAPIHost || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("release metadata URL is not allowlisted")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, release.ReleaseAPI, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "FlintRoute-component-manager")
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("upstream release metadata is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upstream release metadata returned HTTP %d", response.StatusCode)
	}
	var payload struct {
		TagName    string `json:"tag_name"`
		Prerelease bool   `json:"prerelease"`
		Draft      bool   `json:"draft"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil || payload.TagName == "" || payload.Prerelease || payload.Draft {
		return "", errors.New("upstream release metadata is invalid")
	}
	return payload.TagName, nil
}
