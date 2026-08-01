package zapret

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var setupDomainPattern = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)

type SetupRequest struct {
	Binary          string `json:"-"`
	SourceURL       string `json:"source_url"`
	ProviderVersion string `json:"provider_version"`
	BinaryDigest    string `json:"binary_sha256"`
	TestDomain      string `json:"test_domain"`
	QueueNum        int    `json:"queue_num"`
}

type SetupReport struct {
	Ready            bool   `json:"ready"`
	BinaryPresent    bool   `json:"binary_present"`
	BinaryDigest     string `json:"binary_sha256"`
	ProviderVersion  string `json:"provider_version"`
	Architecture     string `json:"architecture"`
	NFQueueAvailable bool   `json:"nfqueue_available"`
	KernelSupport    string `json:"kernel_support"`
	DryRun           bool   `json:"dry_run"`
	TestDomain       string `json:"test_domain"`
	SourcePinned     bool   `json:"source_pinned"`
}

type SetupChecker interface {
	Check(context.Context, SetupRequest) (SetupReport, error)
}

type LocalSetupChecker struct {
	Runner      Runner
	NFTBinary   string
	TempDir     string
	ModulesPath string
	SysModule   string
}

func (c LocalSetupChecker) Check(ctx context.Context, request SetupRequest) (SetupReport, error) {
	if err := validateSetupRequest(request); err != nil {
		return SetupReport{}, err
	}
	runner := c.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	tempDir := c.TempDir
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	strategy := ManagedStrategy(request.QueueNum)
	profile := Profile{
		ID: "setup", Provider: "nfqws-v1", ProviderVersion: request.ProviderVersion,
		BinaryDigest: request.BinaryDigest, RouteType: "zapret", IPFamilies: []string{"ipv4"},
		Transports: []string{"tcp"}, Ports: []uint16{80, 443}, Queue: uint16(request.QueueNum),
		Safety: "reviewed", StrategyDigest: Digest(strategy), Strategy: strategy,
	}
	catalog, err := NewCatalog([]Profile{profile})
	if err != nil {
		return SetupReport{}, err
	}
	provider, err := NewNFQWSv1(request.Binary, tempDir, runner)
	if err != nil {
		return SetupReport{}, err
	}
	verification, err := provider.Validate(ctx, catalog, profile.ID)
	if err != nil {
		return SetupReport{}, err
	}
	nftBinary := c.NFTBinary
	if nftBinary == "" {
		nftBinary = "/usr/sbin/nft"
	}
	nftCandidate, err := writeNFQueueCandidate(tempDir, request.QueueNum)
	if err != nil {
		return SetupReport{}, err
	}
	defer os.Remove(nftCandidate)
	if _, err := runner.Run(ctx, nftBinary, "-c", "-f", nftCandidate); err != nil {
		return SetupReport{}, errors.New("NFQUEUE nftables capability check failed")
	}
	moduleState := detectNFQueueModule(c.ModulesPath, c.SysModule)
	return SetupReport{
		Ready: true, BinaryPresent: true, BinaryDigest: verification.BinaryDigest,
		ProviderVersion: verification.ProviderVersion, Architecture: runtime.GOARCH,
		NFQueueAvailable: true, KernelSupport: moduleState, DryRun: verification.DryRun,
		TestDomain: strings.ToLower(request.TestDomain), SourcePinned: true,
	}, nil
}

func ManagedStrategy(queue int) []byte {
	return []byte(fmt.Sprintf("--qnum=%d\n--filter-tcp=80\n--dpi-desync=fake,fakedsplit\n--dpi-desync-split-pos=method+2\n--dpi-desync-fooling=md5sig\n--new\n--filter-tcp=443\n--dpi-desync=fake\n--dpi-desync-ttl=3\n--orig-ttl=1\n--orig-mod-start=s1\n--orig-mod-cutoff=d1\n", queue))
}

func validateSetupRequest(request SetupRequest) error {
	if !filepath.IsAbs(request.Binary) || request.QueueNum < 1 || request.QueueNum > 65535 {
		return errors.New("absolute nfqws binary path and queue 1..65535 are required")
	}
	if !versionPattern.MatchString(request.ProviderVersion) || !digestPattern.MatchString(request.BinaryDigest) {
		return errors.New("pinned nfqws version and SHA-256 are required")
	}
	parsed, err := url.ParseRequestURI(request.SourceURL)
	lower := strings.ToLower(request.SourceURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(lower, "latest") || !strings.Contains(parsed.Path, request.ProviderVersion) {
		return errors.New("source URL must be immutable HTTPS and contain the pinned version")
	}
	if !setupDomainPattern.MatchString(strings.TrimSpace(request.TestDomain)) {
		return errors.New("test_domain must be a DNS hostname")
	}
	return nil
}

func writeNFQueueCandidate(dir string, queue int) (string, error) {
	file, err := os.CreateTemp(dir, "nfqueue-capability-*.nft")
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
	content := fmt.Sprintf("table inet router_policy_capability { chain probe { type filter hook output priority 0; tcp dport 443 queue num %d bypass; } }\n", queue)
	if _, err := file.WriteString(content); err != nil {
		return "", err
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

func detectNFQueueModule(modulesPath, sysModule string) string {
	if modulesPath == "" {
		modulesPath = "/proc/modules"
	}
	if sysModule == "" {
		sysModule = "/sys/module/nfnetlink_queue"
	}
	if raw, err := os.ReadFile(modulesPath); err == nil {
		text := string(raw)
		if strings.Contains(text, "nfnetlink_queue") || strings.Contains(text, "nft_queue") {
			return "loaded"
		}
	}
	if info, err := os.Stat(sysModule); err == nil && info.IsDir() {
		return "built_in_or_loaded"
	}
	return "verified_by_nft_check"
}
