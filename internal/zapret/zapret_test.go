package zapret

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const reviewedStrategy = `--qnum=200
--filter-tcp=80
--dpi-desync=fake,fakedsplit
--dpi-desync-split-pos=method+2
--dpi-desync-fooling=md5sig
--new
--filter-tcp=443
--dpi-desync=fake
--dpi-desync-ttl=3
--orig-ttl=1
--orig-mod-start=s1
--orig-mod-cutoff=d1
`

type providerRunner struct {
	t          *testing.T
	version    string
	versionErr error
	dryRunErr  error
	calls      [][]string
}

func (r *providerRunner) Run(_ context.Context, binary string, args ...string) ([]byte, error) {
	r.t.Helper()
	r.calls = append(r.calls, append([]string{binary}, args...))
	if len(args) == 1 && args[0] == "--version" {
		return []byte(r.version), r.versionErr
	}
	if len(args) != 1 || !strings.HasPrefix(args[0], "@") {
		r.t.Fatalf("unexpected provider invocation: %q", args)
	}
	path := strings.TrimPrefix(args[0], "@")
	info, err := os.Stat(path)
	if err != nil {
		r.t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		r.t.Fatalf("candidate mode = %o, want 600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		r.t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "\n--dry-run\n") || strings.Count(string(raw), "--dry-run") != 1 {
		r.t.Fatalf("dry-run is not embedded exactly once: %q", raw)
	}
	return nil, r.dryRunErr
}

func TestCatalogRejectsUnreviewedAndUnsafeProfiles(t *testing.T) {
	binaryDigest := Digest([]byte("binary"))
	valid := testProfile(binaryDigest)
	if _, err := NewCatalog([]Profile{valid}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*Profile)
	}{
		{"digest", func(profile *Profile) { profile.StrategyDigest = Digest([]byte("other")) }},
		{"provider", func(profile *Profile) { profile.Provider = "nfqws2" }},
		{"safety", func(profile *Profile) { profile.Safety = "generated" }},
		{"shell", func(profile *Profile) {
			profile.Strategy = []byte("--qnum=200\n--dpi-desync=fake;reboot\n")
			profile.StrategyDigest = Digest(profile.Strategy)
		}},
		{"path", func(profile *Profile) {
			profile.Strategy = []byte("--qnum=200\n--hostlist=/tmp/list\n")
			profile.StrategyDigest = Digest(profile.Strategy)
		}},
		{"dry-run", func(profile *Profile) {
			profile.Strategy = []byte("--qnum=200\n--dry-run\n")
			profile.StrategyDigest = Digest(profile.Strategy)
		}},
		{"scope", func(profile *Profile) { profile.Ports = []uint16{443} }},
		{"separator", func(profile *Profile) {
			profile.Strategy = append(profile.Strategy, []byte("--new\n")...)
			profile.StrategyDigest = Digest(profile.Strategy)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := valid
			test.mutate(&profile)
			if _, err := NewCatalog([]Profile{profile}); err == nil {
				t.Fatal("unsafe profile was accepted")
			}
		})
	}
}

func TestCatalogIsBoundedAndReturnsCopies(t *testing.T) {
	profiles := make([]Profile, MaxProfiles+1)
	for i := range profiles {
		profiles[i] = testProfile(Digest([]byte("binary")))
		profiles[i].ID = "profile-" + string(rune('a'+i))
	}
	if _, err := NewCatalog(profiles); err == nil {
		t.Fatal("oversized catalog was accepted")
	}
	catalog, err := NewCatalog(profiles[:1])
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := catalog.Lookup(profiles[0].ID)
	if !ok || catalog.Len() != 1 {
		t.Fatal("catalog lookup failed")
	}
	profile.Strategy[0] = 'x'
	again, _ := catalog.Lookup(profiles[0].ID)
	if again.Strategy[0] == 'x' {
		t.Fatal("catalog returned mutable internal storage")
	}
}

func TestNFQWSv1ChecksVersionDigestAndEmbeddedDryRun(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "nfqws")
	if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	profile := testProfile(Digest([]byte("binary")))
	catalog, err := NewCatalog([]Profile{profile})
	if err != nil {
		t.Fatal(err)
	}
	runner := &providerRunner{t: t, version: "github version v72.12 (test)\n"}
	provider, err := NewNFQWSv1(binary, dir, runner)
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Validate(context.Background(), catalog, profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !result.DryRun || result.ProviderVersion != "72.12" || result.BinaryDigest != profile.BinaryDigest || len(runner.calls) != 2 {
		t.Fatalf("unexpected verification: %+v calls=%d", result, len(runner.calls))
	}
}

func TestNFQWSv1FailsBeforeDryRunOnVersionOrDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "nfqws")
	if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	t.Run("digest", func(t *testing.T) {
		profile := testProfile(Digest([]byte("other")))
		catalog, err := NewCatalog([]Profile{profile})
		if err != nil {
			t.Fatal(err)
		}
		runner := &providerRunner{t: t, version: "github version v72.12\n"}
		provider, _ := NewNFQWSv1(binary, dir, runner)
		if _, err := provider.Validate(context.Background(), catalog, profile.ID); err == nil || len(runner.calls) != 0 {
			t.Fatal("digest mismatch reached provider execution")
		}
	})

	t.Run("version", func(t *testing.T) {
		profile := testProfile(Digest([]byte("binary")))
		catalog, err := NewCatalog([]Profile{profile})
		if err != nil {
			t.Fatal(err)
		}
		runner := &providerRunner{t: t, version: "github version v73.0\n", dryRunErr: errors.New("must not run")}
		provider, _ := NewNFQWSv1(binary, dir, runner)
		if _, err := provider.Validate(context.Background(), catalog, profile.ID); err == nil || len(runner.calls) != 1 {
			t.Fatal("version mismatch reached candidate dry-run")
		}
	})
}

func testProfile(binaryDigest string) Profile {
	strategy := []byte(reviewedStrategy)
	return Profile{
		ID: "zapret-v1-tls-fake-ttl3", Provider: "nfqws-v1", ProviderVersion: "72.12",
		BinaryDigest: binaryDigest, RouteType: "zapret", IPFamilies: []string{"ipv4"},
		Transports: []string{"tcp"}, Ports: []uint16{80, 443}, Queue: 200,
		Safety: "reviewed", StrategyDigest: Digest(strategy), Strategy: strategy,
	}
}
