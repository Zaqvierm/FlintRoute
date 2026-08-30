package component

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ExecCommandRunner struct{}

func (ExecCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	return command.CombinedOutput()
}

type OpenWrtDriver struct {
	StateDir          string
	XrayBinary        string
	XrayService       string
	ZapretBinary      string
	ZapretService     string
	ZapretRoot        string
	TGWSBinary        string
	TGWSService       string
	TGWSConfigDir     string
	TGWSLocalProbe    func(context.Context, string) error
	TGWSUpstreamProbe func(context.Context, string) error
	Runner            CommandRunner
	Now               func() time.Time
}

func (d OpenWrtDriver) Platform(ctx context.Context) (Platform, error) {
	runner := d.runner()
	machineRaw, err := runner.Run(ctx, "uname", "-m")
	if err != nil {
		return Platform{}, errors.New("uname failed")
	}
	platform := Platform{GOARCH: runtime.GOARCH, Machine: strings.TrimSpace(string(machineRaw))}
	if _, err := exec.LookPath("opkg"); err == nil {
		platform.PackageManager = "opkg"
		raw, runErr := runner.Run(ctx, "opkg", "print-architecture")
		if runErr != nil {
			return Platform{}, errors.New("opkg architecture detection failed")
		}
		platform.PackageArchitectures = parseOpkgArchitectures(string(raw))
	} else if _, err := exec.LookPath("apk"); err == nil {
		platform.PackageManager = "apk"
	}
	return platform, nil
}

func (d OpenWrtDriver) Inspect(ctx context.Context, kind Kind) (Health, bool, string, error) {
	binary, service, err := d.paths(kind)
	if err != nil {
		return Health{}, false, "", err
	}
	info, err := os.Lstat(binary)
	if errors.Is(err, os.ErrNotExist) {
		return Health{State: "not_installed", ServiceState: "absent"}, false, "", nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0o111 == 0 {
		return Health{State: "failed", ServiceState: "unknown", Reason: "component binary is unsafe"}, true, "", nil
	}
	version := d.detectVersion(ctx, kind, binary)
	health, healthErr := d.healthFor(ctx, kind, binary, service)
	if kind == KindZapret {
		ready, runtimeErr := d.zapretRuntimeReady()
		if runtimeErr != nil {
			health.State = "failed"
			health.Ready = false
			health.Reason = "Zapret calibration runtime is unsafe"
			return health, true, version, nil
		}
		if !ready {
			health.State = "degraded"
			health.Ready = false
			health.Reason = "Zapret calibration runtime is missing; reinstall the component"
		}
	}
	return health, true, version, healthErr
}

func (d OpenWrtDriver) zapretRuntimeReady() (bool, error) {
	root := defaultString(d.ZapretRoot, "/usr/lib/router-policy/components/zapret")
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("unsafe Zapret runtime root")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		complete, completeErr := zapretVersionRuntimeReady(filepath.Join(root, entry.Name()))
		if completeErr != nil {
			return false, completeErr
		}
		if complete {
			return true, nil
		}
	}
	return false, nil
}

func (d OpenWrtDriver) Preflight(ctx context.Context, release Release, asset Asset) (Preflight, error) {
	platform, err := d.Platform(ctx)
	if err != nil {
		return Preflight{}, err
	}
	report := Preflight{
		Architecture: asset.Architecture, PackageManager: platform.PackageManager,
		RequiredBytes: release.MinimumFreeByte,
	}
	free, err := d.freeBytes(ctx)
	if err != nil {
		return report, err
	}
	report.FreeBytes = free
	if free < release.MinimumFreeByte {
		report.Reason = "insufficient storage"
		report.Missing = append(report.Missing, "free_storage")
		return report, nil
	}
	switch release.Kind {
	case KindXray:
		report.Capabilities = append(report.Capabilities, "zip_extract", "procd_service")
	case KindZapret:
		if _, err := exec.LookPath("nft"); err != nil {
			report.Missing = append(report.Missing, "nftables")
		}
		if !nfqueueAvailable() {
			report.Missing = append(report.Missing, "nfqueue_kernel_support")
		}
		report.Capabilities = append(report.Capabilities, "embedded_archive", "managed_nfqueue")
	case KindTGWS:
		if asset.PackageType == "ipk" && platform.PackageManager != "opkg" {
			report.Missing = append(report.Missing, "opkg")
		}
		report.Capabilities = append(report.Capabilities, "upstream_openwrt_package", "procd_service")
	}
	if len(report.Missing) > 0 {
		report.Reason = "required capabilities are missing: " + strings.Join(report.Missing, ", ")
		return report, nil
	}
	report.Ready = true
	return report, nil
}

func (d OpenWrtDriver) Install(ctx context.Context, release Release, asset Asset, artifact string, previous Record) (Record, error) {
	if release.Kind == KindTGWS {
		return d.installTGWS(ctx, release, asset, artifact, previous)
	}
	target, service, err := d.paths(release.Kind)
	if err != nil {
		return Record{}, err
	}
	rollbackPath, err := d.backupBinary(release.Kind, previous.Version, target)
	if err != nil {
		return Record{}, err
	}
	temporary, err := os.CreateTemp(d.StateDir, ".component-extract-*")
	if err != nil {
		return Record{}, err
	}
	extracted := temporary.Name()
	_ = temporary.Close()
	defer os.Remove(extracted)
	if err := extractMember(artifact, asset, extracted); err != nil {
		return Record{}, err
	}
	if release.Kind == KindZapret {
		if err := d.installZapretRuntime(artifact, release); err != nil {
			return Record{}, err
		}
	}
	wasRunning := d.serviceRunning(ctx, service)
	if err := installExecutable(extracted, target); err != nil {
		return Record{}, err
	}
	if wasRunning {
		if _, err := d.runner().Run(ctx, service, "restart"); err != nil {
			return Record{}, errors.New("component service restart failed")
		}
	}
	return Record{
		Kind: release.Kind, Installed: true, Version: release.Version, Source: release.Source,
		Checksum: asset.SHA256, Architecture: asset.Architecture, PackageType: asset.PackageType,
		InstalledAt: d.now(), RollbackVersion: previous.Version, RollbackPath: rollbackPath,
	}, nil
}

func (d OpenWrtDriver) Restart(ctx context.Context, kind Kind) error {
	_, service, err := d.paths(kind)
	if err != nil {
		return err
	}
	if _, err := d.runner().Run(ctx, service, "restart"); err != nil {
		return errors.New("component service restart failed")
	}
	health, err := d.Health(ctx, kind)
	if err != nil || !health.Ready {
		return fmt.Errorf("component did not recover after restart: %s", health.Reason)
	}
	return nil
}

func (d OpenWrtDriver) Rollback(ctx context.Context, record Record) (Record, error) {
	if record.RollbackPath == "" || record.RollbackVersion == "" {
		return Record{}, errors.New("rollback artifact is unavailable")
	}
	info, err := os.Lstat(record.RollbackPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Record{}, errors.New("rollback artifact is unsafe")
	}
	target, service, err := d.paths(record.Kind)
	if err != nil {
		return Record{}, err
	}
	if err := installExecutable(record.RollbackPath, target); err != nil {
		return Record{}, err
	}
	if d.serviceRunning(ctx, service) {
		if _, err := d.runner().Run(ctx, service, "restart"); err != nil {
			return Record{}, errors.New("rolled back component failed to restart")
		}
	}
	record.Version, record.RollbackVersion = record.RollbackVersion, record.Version
	record.InstalledAt = d.now()
	return record, nil
}

func (d OpenWrtDriver) Uninstall(ctx context.Context, kind Kind, preserveConfig bool) error {
	target, service, err := d.paths(kind)
	if err != nil {
		return err
	}
	_, _ = d.runner().Run(ctx, service, "stop")
	_, _ = d.runner().Run(ctx, service, "disable")
	if kind == KindTGWS {
		if preserveConfig {
			if err := d.backupTGWSConfig(); err != nil {
				return err
			}
		}
		if _, err := d.runner().Run(ctx, "opkg", "remove", "tg-ws-proxy"); err != nil {
			return errors.New("tg-ws-proxy package removal failed")
		}
		return nil
	}
	if kind == KindZapret && !preserveConfig {
		root := defaultString(d.ZapretRoot, "/usr/lib/router-policy/components/zapret")
		if err := removeOwnedTree(root); err != nil {
			return err
		}
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to remove unsafe component target")
	}
	return os.Remove(target)
}

func (d OpenWrtDriver) installZapretRuntime(artifact string, release Release) error {
	version := safeVersion(release.Version)
	if version == "unknown" {
		return errors.New("Zapret release version is unsafe")
	}
	root := defaultString(d.ZapretRoot, "/usr/lib/router-policy/components/zapret")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	target := filepath.Join(root, version)
	if ready, readyErr := zapretVersionRuntimeReady(target); readyErr != nil {
		return errors.New("existing Zapret runtime is unsafe")
	} else if ready {
		return nil
	}
	staging, err := os.MkdirTemp(root, "."+version+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	prefix := strings.TrimPrefix(release.Version, "v")
	archivePrefix := "zapret-v" + prefix + "/"
	if err := extractZapretRuntime(artifact, archivePrefix, staging); err != nil {
		return err
	}
	if info, statErr := os.Lstat(target); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("existing Zapret runtime is unsafe")
		}
		backup, backupErr := os.MkdirTemp(root, "."+version+"-previous-")
		if backupErr != nil {
			return backupErr
		}
		if removeErr := os.Remove(backup); removeErr != nil {
			return removeErr
		}
		if renameErr := os.Rename(target, backup); renameErr != nil {
			return errors.New("stage existing Zapret runtime replacement failed")
		}
		if renameErr := os.Rename(staging, target); renameErr != nil {
			_ = os.Rename(backup, target)
			return errors.New("install Zapret calibration runtime atomically failed")
		}
		if removeErr := os.RemoveAll(backup); removeErr != nil {
			return errors.New("remove replaced Zapret runtime failed")
		}
		return nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errors.New("inspect existing Zapret runtime failed")
	}
	if err := os.Rename(staging, target); err != nil {
		return errors.New("install Zapret calibration runtime atomically failed")
	}
	return nil
}

func extractZapretRuntime(artifact, archivePrefix, destination string) error {
	file, err := os.Open(artifact)
	if err != nil {
		return err
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return errors.New("open Zapret archive failed")
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	selected := 0
	var total int64
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return errors.New("read Zapret archive failed")
		}
		name := filepath.ToSlash(header.Name)
		if !strings.HasPrefix(name, archivePrefix) {
			continue
		}
		relative := strings.TrimPrefix(name, archivePrefix)
		allowed := relative == "blockcheck.sh" || relative == "config.default" || strings.HasPrefix(relative, "common/") ||
			relative == "binaries/linux-arm64/nfqws" || relative == "binaries/linux-arm64/tpws" || relative == "binaries/linux-arm64/mdig"
		if !allowed || relative == "" || header.FileInfo().IsDir() {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > 8<<20 {
			return errors.New("Zapret runtime archive contains an unsafe member")
		}
		clean := filepath.Clean(filepath.FromSlash(relative))
		if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			return errors.New("Zapret runtime archive contains path traversal")
		}
		runtimeRelative := clean
		switch relative {
		case "binaries/linux-arm64/nfqws":
			runtimeRelative = filepath.FromSlash("nfq/nfqws")
		case "binaries/linux-arm64/tpws":
			runtimeRelative = filepath.FromSlash("tpws/tpws")
		case "binaries/linux-arm64/mdig":
			runtimeRelative = filepath.FromSlash("mdig/mdig")
		}
		total += header.Size
		selected++
		if total > 16<<20 || selected > 128 {
			return errors.New("Zapret runtime archive exceeds extraction limits")
		}
		output := filepath.Join(destination, runtimeRelative)
		if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o600)
		if relative == "blockcheck.sh" || strings.HasPrefix(relative, "common/") || strings.HasPrefix(relative, "binaries/") {
			mode = 0o700
		}
		out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(out, reader, header.Size)
		closeErr := out.Close()
		if copyErr != nil || closeErr != nil {
			return errors.New("extract Zapret runtime member failed")
		}
	}
	for _, required := range zapretRuntimeMembers() {
		info, err := os.Lstat(filepath.Join(destination, filepath.FromSlash(required)))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Zapret archive is missing a required calibration member")
		}
	}
	return nil
}

func zapretRuntimeMembers() []string {
	return []string{"blockcheck.sh", "config.default", "common/base.sh", "nfq/nfqws", "tpws/tpws", "mdig/mdig"}
}

func zapretVersionRuntimeReady(target string) (bool, error) {
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("unsafe Zapret version runtime")
	}
	for _, relative := range zapretRuntimeMembers() {
		member, memberErr := os.Lstat(filepath.Join(target, filepath.FromSlash(relative)))
		executableRequired := relative != "config.default"
		if errors.Is(memberErr, os.ErrNotExist) {
			return false, nil
		}
		if memberErr != nil || !member.Mode().IsRegular() || member.Mode()&os.ModeSymlink != 0 ||
			(executableRequired && member.Mode()&0o111 == 0) {
			return false, errors.New("unsafe Zapret runtime member")
		}
	}
	return true, nil
}

func removeOwnedTree(root string) error {
	clean := filepath.Clean(root)
	if clean == "." || clean == string(os.PathSeparator) || !filepath.IsAbs(clean) || filepath.Base(clean) != "zapret" {
		return errors.New("refusing unsafe Zapret runtime cleanup")
	}
	info, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing unsafe Zapret runtime cleanup")
	}
	return os.RemoveAll(clean)
}

func (d OpenWrtDriver) Health(ctx context.Context, kind Kind) (Health, error) {
	binary, service, err := d.paths(kind)
	if err != nil {
		return Health{}, err
	}
	return d.healthFor(ctx, kind, binary, service)
}

func (d OpenWrtDriver) healthFor(ctx context.Context, kind Kind, binary, service string) (Health, error) {
	if d.detectVersion(ctx, kind, binary) == "" {
		return Health{State: "failed", ServiceState: "unknown", Reason: "component version check failed"}, nil
	}
	running := d.serviceRunning(ctx, service)
	if !running {
		// The production controller is non-root.  OpenWrt's rc.common status
		// command may be unreadable to it because procd tries to create a
		// root-only lock file.  A read-only /proc check for the exact executable
		// keeps component status truthful without granting the controller a
		// privileged init-script execution path.
		running = processBinaryRunning(binary)
	}
	state := "ready"
	reason := ""
	if !running {
		state = "installed"
		reason = "component is installed; service is stopped until its route or transport is configured"
	}
	if kind == KindTGWS && !running {
		state = "needs_configuration"
		reason = "TG WS Proxy is installed but not enabled; configure and verify a Telegram client path first"
		return Health{State: state, ServiceState: "stopped", Ready: false, Reason: reason}, nil
	}
	if kind == KindTGWS {
		status, err := d.TGWSStatus(ctx)
		if err != nil {
			return Health{}, err
		}
		return Health{
			State: status.State, ServiceState: map[bool]string{true: "running", false: "stopped"}[status.Running],
			Ready: status.LocalListener && status.UpstreamReachable, Reason: status.Reason, LastSuccessful: status.CheckedAt,
		}, nil
	}
	return Health{State: state, ServiceState: map[bool]string{true: "running", false: "stopped"}[running], Ready: true, Reason: reason, LastSuccessful: d.now()}, nil
}

func (d OpenWrtDriver) installTGWS(ctx context.Context, release Release, asset Asset, artifact string, previous Record) (Record, error) {
	if asset.PackageType != "ipk" {
		return Record{}, errors.New("unsupported TG WS Proxy package type")
	}
	if err := ensureTGWSDisabled(); err != nil {
		return Record{}, err
	}
	rollbackPath := ""
	if previous.Installed {
		rollbackPath, _ = d.backupBinary(KindTGWS, previous.Version, defaultString(d.TGWSBinary, "/usr/bin/tg-ws-proxy"))
	}
	if _, err := d.runner().Run(ctx, "opkg", "install", artifact); err != nil {
		return Record{}, errors.New("tg-ws-proxy package installation failed")
	}
	_, _ = d.runner().Run(ctx, d.servicePath(KindTGWS), "stop")
	_, _ = d.runner().Run(ctx, d.servicePath(KindTGWS), "disable")
	if err := secureTGWSConfig(); err != nil {
		return Record{}, err
	}
	return Record{
		Kind: release.Kind, Installed: true, Version: release.Version, Source: release.Source,
		Checksum: asset.SHA256, Architecture: asset.Architecture, PackageType: asset.PackageType,
		InstalledAt: d.now(), RollbackVersion: previous.Version, RollbackPath: rollbackPath,
	}, nil
}

func (d OpenWrtDriver) paths(kind Kind) (string, string, error) {
	switch kind {
	case KindXray:
		return defaultString(d.XrayBinary, "/usr/bin/xray"), defaultString(d.XrayService, "/etc/init.d/router-policy-xray"), nil
	case KindZapret:
		return defaultString(d.ZapretBinary, "/usr/bin/nfqws"), defaultString(d.ZapretService, "/etc/init.d/router-policy-zapret"), nil
	case KindTGWS:
		return defaultString(d.TGWSBinary, "/usr/bin/tg-ws-proxy"), defaultString(d.TGWSService, "/etc/init.d/tg-ws-proxy"), nil
	default:
		return "", "", errors.New("unsupported component")
	}
}

func (d OpenWrtDriver) servicePath(kind Kind) string {
	_, service, _ := d.paths(kind)
	return service
}

func (d OpenWrtDriver) runner() CommandRunner {
	if d.Runner != nil {
		return d.Runner
	}
	return ExecCommandRunner{}
}

func (d OpenWrtDriver) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

func (d OpenWrtDriver) serviceRunning(ctx context.Context, service string) bool {
	if service == "" {
		return false
	}
	_, err := d.runner().Run(ctx, service, "running")
	if err == nil {
		return true
	}
	_, err = d.runner().Run(ctx, service, "status")
	return err == nil
}

func processBinaryRunning(binary string) bool {
	if runtime.GOOS == "windows" || strings.TrimSpace(binary) == "" {
		return false
	}
	want := filepath.Clean(binary)
	if resolved, err := filepath.EvalSymlinks(binary); err == nil {
		want = filepath.Clean(resolved)
	}
	wantBase := filepath.Base(want)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil || len(cmdline) == 0 {
			continue
		}
		first := strings.TrimSpace(strings.SplitN(string(cmdline), "\x00", 2)[0])
		if first == want || filepath.Base(first) == wantBase {
			return true
		}
	}
	return false
}

func (d OpenWrtDriver) detectVersion(ctx context.Context, kind Kind, binary string) string {
	if kind == KindTGWS {
		raw, err := d.runner().Run(ctx, "opkg", "status", "tg-ws-proxy")
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "Version:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
			}
		}
		return ""
	}
	args := []string{"--version"}
	if kind == KindXray {
		args = []string{"version"}
	}
	raw, err := d.runner().Run(ctx, binary, args...)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
	if len(line) > 128 {
		line = line[:128]
	}
	return line
}

func (d OpenWrtDriver) backupBinary(kind Kind, version, target string) (string, error) {
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("existing component binary is unsafe")
	}
	if version == "" {
		version = "previous"
	}
	dir := filepath.Join(d.StateDir, "components", "backups", string(kind), safeVersion(version))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, filepath.Base(target))
	if err := copyRegularFile(target, path, 0o700); err != nil {
		return "", err
	}
	return path, nil
}

func (d OpenWrtDriver) freeBytes(ctx context.Context) (int64, error) {
	raw, err := d.runner().Run(ctx, "df", "-Pk", d.StateDir)
	if err != nil {
		return 0, errors.New("free storage check failed")
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 {
		return 0, errors.New("free storage output is invalid")
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return 0, errors.New("free storage output is invalid")
	}
	blocks, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil || blocks < 0 {
		return 0, errors.New("free storage output is invalid")
	}
	return blocks * 1024, nil
}

func parseOpkgArchitectures(raw string) []string {
	type weighted struct {
		name   string
		weight int
	}
	var values []weighted
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "arch" || fields[1] == "all" || fields[1] == "noarch" {
			continue
		}
		weight, err := strconv.Atoi(fields[2])
		if err == nil {
			values = append(values, weighted{name: fields[1], weight: weight})
		}
	}
	sort.SliceStable(values, func(i, j int) bool { return values[i].weight > values[j].weight })
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.name)
	}
	return result
}

func extractMember(artifact string, asset Asset, output string) error {
	switch asset.PackageType {
	case "zip":
		archive, err := zip.OpenReader(artifact)
		if err != nil {
			return errors.New("component ZIP is invalid")
		}
		defer archive.Close()
		for _, file := range archive.File {
			if filepath.ToSlash(file.Name) != asset.Member || file.FileInfo().IsDir() || file.Mode()&os.ModeSymlink != 0 {
				continue
			}
			reader, err := file.Open()
			if err != nil {
				return err
			}
			err = writeLimited(reader, output, 64<<20)
			_ = reader.Close()
			return err
		}
	case "tar.gz":
		file, err := os.Open(artifact)
		if err != nil {
			return err
		}
		defer file.Close()
		compressed, err := gzip.NewReader(file)
		if err != nil {
			return errors.New("component tarball is invalid")
		}
		defer compressed.Close()
		reader := tar.NewReader(compressed)
		for {
			header, err := reader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return errors.New("component tarball is invalid")
			}
			if filepath.ToSlash(header.Name) == asset.Member && header.Typeflag == tar.TypeReg {
				return writeLimited(io.LimitReader(reader, header.Size), output, 64<<20)
			}
		}
	default:
		return errors.New("unsupported component archive")
	}
	return errors.New("component archive member is missing")
}

func writeLimited(reader io.Reader, path string, max int64) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o700)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(file, io.LimitReader(reader, max+1))
	if copyErr != nil || written > max {
		_ = file.Close()
		return errors.New("component binary exceeds size limit")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func installExecutable(source, target string) error {
	if !filepath.IsAbs(target) {
		return errors.New("component target must be absolute")
	}
	if info, err := os.Lstat(target); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("component target is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".component-*")
	if err != nil {
		return err
	}
	path := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(temporary, input)
	_ = input.Close()
	if copyErr != nil {
		return copyErr
	}
	if err := temporary.Chmod(0o755); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(path, target); err != nil {
		return err
	}
	ok = true
	return nil
}

func copyRegularFile(source, target string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".backup-*")
	if err != nil {
		return err
	}
	path := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := io.Copy(temporary, input); err != nil {
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(path, target); err != nil {
		return err
	}
	ok = true
	return nil
}

func nfqueueAvailable() bool {
	if info, err := os.Stat("/sys/module/nfnetlink_queue"); err == nil && info.IsDir() {
		return true
	}
	raw, err := os.ReadFile("/proc/modules")
	return err == nil && (strings.Contains(string(raw), "nfnetlink_queue") || strings.Contains(string(raw), "nft_queue"))
}

func ensureTGWSDisabled() error {
	path := "/etc/config/tg-ws-proxy"
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("config tg-ws-proxy 'main'\n\toption enabled '0'\n\toption user 'root'\n"), 0o600)
}

func secureTGWSConfig() error {
	dir := "/etc/tg-ws-proxy"
	if err := os.Chmod(dir, 0o700); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, name := range []string{"config.conf", "secret.conf"} {
		path := filepath.Join(dir, name)
		if info, err := os.Lstat(path); err == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("TG WS Proxy config is unsafe")
			}
			if err := os.Chmod(path, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d OpenWrtDriver) backupTGWSConfig() error {
	source := "/etc/tg-ws-proxy"
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("TG WS Proxy config directory is unsafe")
	}
	target := filepath.Join(d.StateDir, "components", "backups", string(KindTGWS), "user-config")
	if err := os.MkdirAll(target, 0o700); err != nil {
		return err
	}
	for _, name := range []string{"config.conf", "secret.conf"} {
		path := filepath.Join(source, name)
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := copyRegularFile(path, filepath.Join(target, name), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func safeVersion(value string) string {
	var result strings.Builder
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '-' || char == '_' {
			result.WriteRune(char)
		}
	}
	if result.Len() == 0 {
		return "unknown"
	}
	return result.String()
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
