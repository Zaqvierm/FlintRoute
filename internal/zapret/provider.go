package zapret

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
)

const maxProviderOutput = 64 * 1024

var providerVersionOutput = regexp.MustCompile(`(?m)\bversion\s+v([0-9]+(?:\.[0-9]+){1,2})\b`)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ZapretProvider interface {
	Validate(context.Context, *Catalog, string) (Verification, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	output := &limitedBuffer{limit: maxProviderOutput}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if output.exceeded {
		return nil, errors.New("Zapret provider output limit exceeded")
	}
	return output.Bytes(), err
}

type NFQWSv1 struct {
	binary  string
	tempDir string
	runner  Runner
}

var _ ZapretProvider = (*NFQWSv1)(nil)

type Verification struct {
	ProfileID       string `json:"profile_id"`
	Provider        string `json:"provider"`
	ProviderVersion string `json:"provider_version"`
	BinaryDigest    string `json:"binary_digest"`
	StrategyDigest  string `json:"strategy_digest"`
	DryRun          bool   `json:"dry_run"`
}

func NewNFQWSv1(binary, tempDir string, runner Runner) (*NFQWSv1, error) {
	if !filepath.IsAbs(binary) {
		return nil, errors.New("nfqws binary path must be absolute")
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	return &NFQWSv1{binary: filepath.Clean(binary), tempDir: tempDir, runner: runner}, nil
}

func (p *NFQWSv1) Validate(ctx context.Context, catalog *Catalog, profileID string) (Verification, error) {
	if p == nil || catalog == nil {
		return Verification{}, errors.New("Zapret provider and catalog are required")
	}
	profile, ok := catalog.Lookup(profileID)
	if !ok {
		return Verification{}, fmt.Errorf("Zapret profile %q is not in the catalog", profileID)
	}
	if profile.Provider != "nfqws-v1" {
		return Verification{}, errors.New("Zapret profile provider mismatch")
	}
	digest, err := verifyBinary(p.binary)
	if err != nil {
		return Verification{}, err
	}
	if digest != profile.BinaryDigest {
		return Verification{}, errors.New("nfqws binary digest mismatch")
	}
	versionRaw, err := p.runner.Run(ctx, p.binary, "--version")
	if err != nil {
		return Verification{}, errors.New("nfqws version check failed")
	}
	match := providerVersionOutput.FindSubmatch(versionRaw)
	if len(match) != 2 || string(match[1]) != profile.ProviderVersion {
		return Verification{}, errors.New("nfqws version mismatch")
	}
	candidate, err := writeDryRunCandidate(p.tempDir, profile.Strategy)
	if err != nil {
		return Verification{}, err
	}
	defer os.Remove(candidate)
	if _, err := p.runner.Run(ctx, p.binary, "@"+candidate); err != nil {
		return Verification{}, errors.New("nfqws candidate dry-run failed")
	}
	return Verification{
		ProfileID: profile.ID, Provider: profile.Provider, ProviderVersion: profile.ProviderVersion,
		BinaryDigest: digest, StrategyDigest: profile.StrategyDigest, DryRun: true,
	}, nil
}

func verifyBinary(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect nfqws binary: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("nfqws path must be an executable regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("nfqws path must be executable")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open nfqws binary: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash nfqws binary: %w", err)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func writeDryRunCandidate(dir string, strategy []byte) (string, error) {
	file, err := os.CreateTemp(dir, "nfqws-candidate-*.conf")
	if err != nil {
		return "", fmt.Errorf("create nfqws candidate: %w", err)
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
		return "", fmt.Errorf("secure nfqws candidate: %w", err)
	}
	if _, err := file.Write(strategy); err != nil {
		return "", fmt.Errorf("write nfqws candidate: %w", err)
	}
	if len(strategy) == 0 || strategy[len(strategy)-1] != '\n' {
		if _, err := file.Write([]byte("\n")); err != nil {
			return "", fmt.Errorf("finish nfqws candidate: %w", err)
		}
	}
	if _, err := file.Write([]byte("--dry-run\n")); err != nil {
		return "", fmt.Errorf("enable nfqws dry-run: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync nfqws candidate: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close nfqws candidate: %w", err)
	}
	ok = true
	return path, nil
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	if w.exceeded {
		return len(p), nil
	}
	remaining := w.limit - w.buffer.Len()
	if remaining <= 0 {
		w.exceeded = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = w.buffer.Write(p[:remaining])
		w.exceeded = true
		return len(p), nil
	}
	return w.buffer.Write(p)
}

func (w *limitedBuffer) Bytes() []byte { return append([]byte(nil), w.buffer.Bytes()...) }
