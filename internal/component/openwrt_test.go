package component

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestParseOpkgArchitecturesUsesPriority(t *testing.T) {
	got := parseOpkgArchitectures("arch all 1\narch aarch64_generic 10\narch aarch64_cortex-a53 20\n")
	want := []string{"aarch64_cortex-a53", "aarch64_generic"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("architectures=%v want=%v", got, want)
	}
}

func TestExtractMemberRejectsTraversalAndSelectsExactMember(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "component.zip")
	file, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	bad, _ := writer.Create("../xray")
	_, _ = bad.Write([]byte("bad"))
	good, _ := writer.Create("xray")
	_, _ = good.Write([]byte("good"))
	_ = writer.Close()
	_ = file.Close()
	output := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(output, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractMember(zipPath, Asset{PackageType: "zip", Member: "xray"}, output); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(output); string(raw) != "good" {
		t.Fatalf("extracted %q", raw)
	}
}

func TestExtractTarMember(t *testing.T) {
	path := filepath.Join(t.TempDir(), "component.tar.gz")
	file, _ := os.Create(path)
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	payload := []byte("nfqws")
	_ = archive.WriteHeader(&tar.Header{Name: "release/binaries/linux-arm64/nfqws", Mode: 0o755, Size: int64(len(payload)), Typeflag: tar.TypeReg})
	_, _ = archive.Write(payload)
	_ = archive.Close()
	_ = compressed.Close()
	_ = file.Close()
	output := filepath.Join(t.TempDir(), "nfqws")
	_ = os.WriteFile(output, nil, 0o600)
	if err := extractMember(path, Asset{PackageType: "tar.gz", Member: "release/binaries/linux-arm64/nfqws"}, output); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(output); string(raw) != "nfqws" {
		t.Fatalf("extracted %q", raw)
	}
}

func TestExtractZapretRuntimeAllowsOnlyCalibrationDependencies(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "zapret.tar.gz")
	file, _ := os.Create(path)
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	members := map[string]string{
		"zapret-v1/blockcheck.sh": "blockcheck", "zapret-v1/config.default": "config",
		"zapret-v1/common/base.sh": "base", "zapret-v1/common/dialog.sh": "dialog",
		"zapret-v1/binaries/linux-arm64/nfqws": "nfqws", "zapret-v1/binaries/linux-arm64/tpws": "tpws", "zapret-v1/binaries/linux-arm64/mdig": "mdig",
		"zapret-v1/install_bin.sh": "must-not-extract",
	}
	for name, payload := range members {
		_ = archive.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(payload)), Typeflag: tar.TypeReg})
		_, _ = archive.Write([]byte(payload))
	}
	_ = archive.Close()
	_ = compressed.Close()
	_ = file.Close()
	destination := filepath.Join(root, "runtime")
	_ = os.Mkdir(destination, 0o700)
	if err := extractZapretRuntime(path, "zapret-v1/", destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "install_bin.sh")); !os.IsNotExist(err) {
		t.Fatal("upstream installer was extracted into the managed runtime")
	}
	for _, relative := range []string{"nfq/nfqws", "tpws/tpws", "mdig/mdig"} {
		if info, err := os.Stat(filepath.Join(destination, filepath.FromSlash(relative))); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("normalized blockcheck runtime member %s is missing: %v", relative, err)
		}
	}
}

func TestInstallZapretRuntimeRepairsIncompleteUpstreamLayout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose OpenWrt executable mode bits")
	}
	root := t.TempDir()
	archivePath := filepath.Join(root, "zapret.tar.gz")
	file, _ := os.Create(archivePath)
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	members := map[string]string{
		"zapret-v72.13/blockcheck.sh": "blockcheck", "zapret-v72.13/config.default": "config",
		"zapret-v72.13/common/base.sh": "base", "zapret-v72.13/binaries/linux-arm64/nfqws": "nfqws",
		"zapret-v72.13/binaries/linux-arm64/tpws": "tpws", "zapret-v72.13/binaries/linux-arm64/mdig": "mdig",
	}
	for name, payload := range members {
		_ = archive.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(payload)), Typeflag: tar.TypeReg})
		_, _ = archive.Write([]byte(payload))
	}
	_ = archive.Close()
	_ = compressed.Close()
	_ = file.Close()
	runtimeRoot := filepath.Join(root, "runtime", "zapret")
	oldVersion := filepath.Join(runtimeRoot, "v72.13")
	if err := os.MkdirAll(oldVersion, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldVersion, "blockcheck.sh"), []byte("incomplete"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldVersion, "stale"), []byte("remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	driver := OpenWrtDriver{ZapretRoot: runtimeRoot}
	if err := driver.installZapretRuntime(archivePath, Release{Version: "v72.13"}); err != nil {
		t.Fatal(err)
	}
	ready, err := zapretVersionRuntimeReady(oldVersion)
	if err != nil || !ready {
		t.Fatalf("repaired runtime is incomplete: ready=%v err=%v", ready, err)
	}
	if _, err := os.Stat(filepath.Join(oldVersion, "stale")); !os.IsNotExist(err) {
		t.Fatal("stale incomplete runtime member survived replacement")
	}
}

func TestInstallExecutableRefusesSymlinkTarget(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("symlink creation is not guaranteed on Windows test hosts")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	realTarget := filepath.Join(dir, "real")
	target := filepath.Join(dir, "target")
	_ = os.WriteFile(source, []byte("new"), 0o700)
	_ = os.WriteFile(realTarget, []byte("old"), 0o700)
	if err := os.Symlink(realTarget, target); err != nil {
		t.Fatal(err)
	}
	if err := installExecutable(source, target); err == nil {
		t.Fatal("symlink target was accepted")
	}
}

func TestZapretRuntimeReadinessRequiresCompleteManagedTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose OpenWrt executable mode bits")
	}
	root := filepath.Join(t.TempDir(), "zapret")
	version := filepath.Join(root, "v72.13")
	for _, relative := range []string{
		"blockcheck.sh", "config.default", "common/base.sh",
		"nfq/nfqws", "tpws/tpws", "mdig/mdig",
	} {
		path := filepath.Join(version, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o755)
		if relative == "config.default" {
			mode = 0o644
		}
		if err := os.WriteFile(path, []byte("fixture"), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(version, 0o755); err != nil {
		t.Fatal(err)
	}
	driver := OpenWrtDriver{ZapretRoot: root}
	ready, err := driver.zapretRuntimeReady()
	if err != nil || !ready {
		t.Fatalf("complete runtime rejected: ready=%v err=%v", ready, err)
	}
	if err := os.Remove(filepath.Join(version, "blockcheck.sh")); err != nil {
		t.Fatal(err)
	}
	ready, err = driver.zapretRuntimeReady()
	if err != nil || ready {
		t.Fatalf("incomplete runtime accepted: ready=%v err=%v", ready, err)
	}
}

func TestZapretRuntimeReadinessRejectsUmaskLockedRuntime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose OpenWrt executable mode bits")
	}
	root := filepath.Join(t.TempDir(), "zapret")
	version := filepath.Join(root, "v72.13")
	for _, relative := range []string{
		"blockcheck.sh", "config.default", "common/base.sh",
		"nfq/nfqws", "tpws/tpws", "mdig/mdig",
	} {
		path := filepath.Join(version, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o755)
		if relative == "config.default" {
			mode = 0o644
		}
		if err := os.WriteFile(path, []byte("fixture"), mode); err != nil {
			t.Fatal(err)
		}
	}
	if ready, err := zapretVersionRuntimeReady(version); err == nil || ready {
		t.Fatalf("umask-locked runtime was accepted: ready=%v err=%v", ready, err)
	}
	if err := normalizeZapretRuntimeModes(version); err != nil {
		t.Fatal(err)
	}
	ready, err := zapretVersionRuntimeReady(version)
	if err != nil || !ready {
		t.Fatalf("normalized runtime was not accepted: ready=%v err=%v", ready, err)
	}
}

func TestProcessBinaryRunningDetectsCurrentExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose a /proc process command line")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !processBinaryRunning(executable) {
		t.Fatalf("current test executable was not found in /proc: %s", executable)
	}
	if processBinaryRunning(filepath.Join(t.TempDir(), "not-running")) {
		t.Fatal("nonexistent executable was reported as running")
	}
}
