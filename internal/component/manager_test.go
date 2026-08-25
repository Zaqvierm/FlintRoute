package component

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

type fakeDriver struct {
	platform           Platform
	preflight          Preflight
	health             Health
	present            bool
	detected           string
	installCalls       int
	healthAfterInstall *Health
	restartCalls       int
	rollbackCalls      int
	uninstallCalls     int
	installRecord      Record
	installErr         error
}

func (d *fakeDriver) Platform(context.Context) (Platform, error) { return d.platform, nil }
func (d *fakeDriver) Inspect(context.Context, Kind) (Health, bool, string, error) {
	return d.health, d.present, d.detected, nil
}
func (d *fakeDriver) Preflight(context.Context, Release, Asset) (Preflight, error) {
	return d.preflight, nil
}
func (d *fakeDriver) Install(_ context.Context, release Release, asset Asset, _ string, previous Record) (Record, error) {
	d.installCalls++
	if d.installErr != nil {
		return Record{}, d.installErr
	}
	record := d.installRecord
	if record.Kind == "" {
		record = Record{Kind: release.Kind, Installed: true, Version: release.Version, Checksum: asset.SHA256, RollbackVersion: previous.Version, RollbackPath: previous.RollbackPath}
	}
	d.present = true
	d.detected = record.Version
	if d.healthAfterInstall != nil {
		d.health = *d.healthAfterInstall
	}
	return record, nil
}
func (d *fakeDriver) Restart(context.Context, Kind) error { d.restartCalls++; return nil }
func (d *fakeDriver) Rollback(_ context.Context, record Record) (Record, error) {
	d.rollbackCalls++
	record.Version, record.RollbackVersion = record.RollbackVersion, record.Version
	return record, nil
}
func (d *fakeDriver) Uninstall(context.Context, Kind, bool) error {
	d.uninstallCalls++
	d.present = false
	return nil
}
func (d *fakeDriver) Health(context.Context, Kind) (Health, error) { return d.health, nil }

type staticTransport struct {
	body   []byte
	status int
}

func (t staticTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: t.status, ContentLength: int64(len(t.body)),
		Body: io.NopCloser(bytes.NewReader(t.body)), Header: make(http.Header),
	}, nil
}

func testManager(t *testing.T, body []byte, driver *fakeDriver) *Manager {
	t.Helper()
	digest := sha256.Sum256(body)
	release := Release{
		Kind: KindXray, Version: "v1.2.3", Source: "https://github.com/XTLS/Xray-core",
		ReleaseAPI: "https://api.github.com/repos/XTLS/Xray-core/releases/latest", MinimumFreeByte: 1,
		Assets: []Asset{{Architecture: "arm64", PackageType: "zip", URL: "https://github.com/XTLS/Xray-core/releases/download/v1.2.3/xray.zip", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(body)), Member: "xray"}},
	}
	return &Manager{
		StateDir: t.TempDir(), RuntimeDir: t.TempDir(), Driver: driver,
		HTTP:    &http.Client{Transport: staticTransport{body: body, status: http.StatusOK}},
		Catalog: map[Kind]Release{KindXray: release},
		Now:     func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) },
	}
}

func TestManagerInstallIsVerifiedAndReinstallIsNoop(t *testing.T) {
	driver := &fakeDriver{
		platform: Platform{GOARCH: "arm64"}, preflight: Preflight{Ready: true},
		health: Health{State: "ready", ServiceState: "running", Ready: true},
	}
	manager := testManager(t, []byte("verified-archive"), driver)
	result, err := manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionInstall})
	if err != nil || !result.Changed || driver.installCalls != 1 {
		t.Fatalf("install: result=%+v calls=%d err=%v", result, driver.installCalls, err)
	}
	result, err = manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionInstall})
	if err != nil || result.Changed || driver.installCalls != 1 {
		t.Fatalf("reinstall was not a no-op: result=%+v calls=%d err=%v", result, driver.installCalls, err)
	}
}

func TestManagerDownloadPreservesIPKPackageSuffix(t *testing.T) {
	body := []byte("verified-ipk")
	digest := sha256.Sum256(body)
	manager := &Manager{
		RuntimeDir: t.TempDir(),
		HTTP:       &http.Client{Transport: staticTransport{body: body, status: http.StatusOK}},
	}
	release := Release{Kind: KindTGWS, Version: "v1.2.3"}
	asset := Asset{
		PackageType: "ipk",
		URL:         "https://github.com/example/project/releases/download/v1.2.3/component.ipk",
		SHA256:      hex.EncodeToString(digest[:]),
		Size:        int64(len(body)),
	}
	path, err := manager.download(context.Background(), release, asset)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(path) != ".ipk" {
		t.Fatalf("opkg artifact lost .ipk suffix: %s", filepath.Base(path))
	}
}

func TestManagerRepairsDegradedSameVersionInstallation(t *testing.T) {
	ready := Health{State: "ready", ServiceState: "stopped", Ready: true}
	driver := &fakeDriver{
		platform: Platform{GOARCH: "arm64"}, preflight: Preflight{Ready: true}, health: ready,
	}
	manager := testManager(t, []byte("verified-archive"), driver)
	if _, err := manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionInstall}); err != nil {
		t.Fatal(err)
	}
	driver.health = Health{State: "degraded", ServiceState: "stopped", Ready: false}
	driver.healthAfterInstall = &ready
	result, err := manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionInstall})
	if err != nil || !result.Changed || driver.installCalls != 2 {
		t.Fatalf("degraded installation was not repaired: result=%+v calls=%d err=%v", result, driver.installCalls, err)
	}
}

func TestManagerRejectsChecksumMismatchBeforeInstall(t *testing.T) {
	driver := &fakeDriver{platform: Platform{GOARCH: "arm64"}, preflight: Preflight{Ready: true}, health: Health{Ready: true}}
	manager := testManager(t, []byte("expected"), driver)
	release := manager.Catalog[KindXray]
	release.Assets[0].SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	manager.Catalog[KindXray] = release
	_, err := manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionInstall})
	if err == nil || driver.installCalls != 0 {
		t.Fatalf("checksum mismatch reached install: calls=%d err=%v", driver.installCalls, err)
	}
}

func TestManagerRejectsUnsupportedArchitectureAndStorageFailure(t *testing.T) {
	driver := &fakeDriver{platform: Platform{GOARCH: "mips64"}, preflight: Preflight{Ready: true}, health: Health{Ready: true}}
	manager := testManager(t, []byte("archive"), driver)
	if _, err := manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionInstall}); err == nil {
		t.Fatal("unsupported architecture was accepted")
	}
	driver.platform.GOARCH = "arm64"
	driver.preflight = Preflight{Ready: false, Reason: "insufficient storage"}
	if _, err := manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionInstall}); err == nil || driver.installCalls != 0 {
		t.Fatalf("failed preflight reached install: calls=%d err=%v", driver.installCalls, err)
	}
}

func TestManagerHealthFailureRollsBackPreviousVersion(t *testing.T) {
	driver := &fakeDriver{
		platform: Platform{GOARCH: "arm64"}, preflight: Preflight{Ready: true},
		health:        Health{Ready: false, Reason: "process exited"},
		installRecord: Record{Kind: KindXray, Installed: true, Version: "v1.2.3", RollbackVersion: "v1.0.0", RollbackPath: filepath.Join(t.TempDir(), "xray")},
	}
	manager := testManager(t, []byte("archive"), driver)
	if err := manager.saveRecord(Record{Kind: KindXray, Installed: true, Version: "v1.0.0"}); err != nil {
		t.Fatal(err)
	}
	result, err := manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionUpdate})
	if err == nil || !result.Rollback || driver.rollbackCalls != 1 {
		t.Fatalf("health failure did not rollback: result=%+v calls=%d err=%v", result, driver.rollbackCalls, err)
	}
}

func TestManagerKeepsInstalledTGWSPendingExplicitConfiguration(t *testing.T) {
	driver := &fakeDriver{
		platform:  Platform{GOARCH: "arm64", PackageManager: "opkg", PackageArchitectures: []string{"aarch64_generic"}},
		preflight: Preflight{Ready: true}, health: Health{State: "needs_configuration", ServiceState: "stopped", Ready: false, Reason: "configure transport"},
	}
	manager := testManager(t, []byte("verified-ipk"), driver)
	release := manager.Catalog[KindXray]
	release.Kind = KindTGWS
	release.Assets[0].Architecture = "aarch64_generic"
	release.Assets[0].PackageType = "ipk"
	manager.Catalog = map[Kind]Release{KindTGWS: release}
	result, err := manager.Execute(context.Background(), Request{Kind: KindTGWS, Action: ActionInstall})
	if err != nil || !result.Changed || result.Status.HealthReady || result.Status.HealthState != "needs_configuration" {
		t.Fatalf("TGWS install must remain pending configuration: result=%+v err=%v", result, err)
	}
}

func TestManagerMarksDetectedUnmanagedComponentAsForeign(t *testing.T) {
	driver := &fakeDriver{
		platform: Platform{GOARCH: "arm64"},
		health:   Health{State: "ready", ServiceState: "running", Ready: true},
		present:  true,
		detected: "Xray 26.3.27",
	}
	manager := testManager(t, []byte("archive"), driver)
	status, err := manager.Status(context.Background(), KindXray, false)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Installed || !status.Detected || status.Managed || status.Ownership != "foreign" {
		t.Fatalf("detected external component was not classified as foreign: %+v", status)
	}
	if status.HealthReady || status.HealthState != "foreign" || status.ServiceState != "foreign" {
		t.Fatalf("foreign component leaked managed health: %+v", status)
	}
}

func TestManagerRejectsMutationOfDetectedForeignComponent(t *testing.T) {
	driver := &fakeDriver{
		platform:  Platform{GOARCH: "arm64"},
		preflight: Preflight{Ready: true},
		health:    Health{State: "ready", ServiceState: "running", Ready: true},
		present:   true,
		detected:  "Xray 26.3.27",
	}
	manager := testManager(t, []byte("archive"), driver)
	if _, err := manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionInstall}); err == nil {
		t.Fatal("install was allowed to overwrite a foreign component")
	}
	if driver.installCalls != 0 {
		t.Fatalf("foreign component reached install: calls=%d", driver.installCalls)
	}
}

func TestManagerMarksRegisteredComponentAsFlintRouteOwned(t *testing.T) {
	driver := &fakeDriver{
		platform: Platform{GOARCH: "arm64"},
		health:   Health{State: "ready", ServiceState: "running", Ready: true},
		present:  true,
		detected: "Xray 26.3.27",
	}
	manager := testManager(t, []byte("archive"), driver)
	if err := manager.saveRecord(Record{Kind: KindXray, Installed: true, Version: "Xray 26.3.27"}); err != nil {
		t.Fatal(err)
	}
	status, err := manager.Status(context.Background(), KindXray, false)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Installed || !status.Detected || !status.Managed || status.Ownership != "flintroute" || !status.HealthReady {
		t.Fatalf("registered component was not classified as owned: %+v", status)
	}
}

func TestManagerUninstallRequiresManagedRecordAndConfirmation(t *testing.T) {
	driver := &fakeDriver{platform: Platform{GOARCH: "arm64"}, health: Health{Ready: true}}
	manager := testManager(t, []byte("archive"), driver)
	if _, err := manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionUninstall, ConfirmDisruption: true}); err == nil {
		t.Fatal("unmanaged component was removed")
	}
	if err := manager.saveRecord(Record{Kind: KindXray, Installed: true, Version: "v1.2.3"}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionUninstall}); err == nil {
		t.Fatal("uninstall without confirmation was accepted")
	}
	result, err := manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionUninstall, ConfirmDisruption: true, PreserveConfig: true})
	if err != nil || !result.Changed || driver.uninstallCalls != 1 {
		t.Fatalf("confirmed uninstall failed: result=%+v calls=%d err=%v", result, driver.uninstallCalls, err)
	}
}

func TestGitHubReleaseSourceRejectsUntrustedMetadataURL(t *testing.T) {
	_, err := (GitHubReleaseSource{}).Latest(context.Background(), Release{ReleaseAPI: "https://example.com/releases/latest"})
	if err == nil {
		t.Fatal("untrusted release metadata URL was accepted")
	}
}

func TestManagerDownloadDoesNotExposeTransportErrors(t *testing.T) {
	driver := &fakeDriver{platform: Platform{GOARCH: "arm64"}, preflight: Preflight{Ready: true}, health: Health{Ready: true}}
	manager := testManager(t, []byte("archive"), driver)
	manager.HTTP.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("token=secret") })
	_, err := manager.Execute(context.Background(), Request{Kind: KindXray, Action: ActionInstall})
	if err == nil || err.Error() != "component download failed" {
		t.Fatalf("transport error leaked or was lost: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
