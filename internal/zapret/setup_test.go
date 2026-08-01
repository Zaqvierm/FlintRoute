package zapret

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type setupRunner struct {
	version string
	calls   [][]string
	failNFT bool
}

func (r *setupRunner) Run(_ context.Context, binary string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{binary}, args...))
	if strings.HasSuffix(binary, "nft") && r.failNFT {
		return nil, os.ErrInvalid
	}
	if len(args) == 1 && args[0] == "--version" {
		return []byte("nfqws version v" + r.version + "\n"), nil
	}
	return []byte("ok\n"), nil
}

func TestLocalSetupCheckerVerifiesPinnedBinaryDryRunAndNFQueue(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "nfqws")
	if err := os.WriteFile(binary, []byte("pinned-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	modules := filepath.Join(dir, "modules")
	if err := os.WriteFile(modules, []byte("nfnetlink_queue 1 0 - Live 0x0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &setupRunner{version: "72.12"}
	checker := LocalSetupChecker{Runner: runner, NFTBinary: filepath.Join(dir, "nft"), TempDir: dir, ModulesPath: modules, SysModule: filepath.Join(dir, "missing")}
	report, err := checker.Check(context.Background(), SetupRequest{
		Binary: binary, SourceURL: "https://downloads.example/nfqws/72.12/nfqws",
		ProviderVersion: "72.12", BinaryDigest: Digest([]byte("pinned-binary")), TestDomain: "example.com", QueueNum: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready || !report.DryRun || !report.NFQueueAvailable || report.KernelSupport != "loaded" || len(runner.calls) != 3 {
		t.Fatalf("bad setup report=%+v calls=%v", report, runner.calls)
	}
}

func TestLocalSetupCheckerRejectsMutableSourceAndNFQueueFailure(t *testing.T) {
	request := SetupRequest{
		Binary: filepath.Join(t.TempDir(), "nfqws"), SourceURL: "https://downloads.example/nfqws/latest/nfqws",
		ProviderVersion: "72.12", BinaryDigest: "sha256:" + strings.Repeat("a", 64), TestDomain: "example.com", QueueNum: 200,
	}
	if _, err := (LocalSetupChecker{}).Check(context.Background(), request); err == nil {
		t.Fatal("mutable latest source was accepted")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "nfqws")
	if err := os.WriteFile(binary, []byte("pinned-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	request.Binary = binary
	request.SourceURL = "https://downloads.example/nfqws/72.12/nfqws"
	request.BinaryDigest = Digest([]byte("pinned-binary"))
	checker := LocalSetupChecker{Runner: &setupRunner{version: "72.12", failNFT: true}, NFTBinary: filepath.Join(dir, "nft"), TempDir: dir}
	if _, err := checker.Check(context.Background(), request); err == nil || !strings.Contains(err.Error(), "NFQUEUE") {
		t.Fatalf("NFQUEUE failure not reported: %v", err)
	}
}
