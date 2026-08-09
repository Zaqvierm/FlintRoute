package platform

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var ipv4LiteralPattern = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\b`)
var decorativeRawIdentityPattern = regexp.MustCompile(`(?m)"(?:ip|mac)"\s*:\s*"[^"\n]*\*[^"\n]*"`)
var glinetRuntimePattern = regexp.MustCompile(`(?i)GL\.iNet|GL-MT6000|Flint 2|glinet_uhttpd|glinet`)

func TestProductionSourcesDoNotContainPrivateEnvironmentAddresses(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	allowedProtocolRanges := map[string]map[string]bool{
		"internal/artifact/artifact.go":  {"10.0.0.0/8": true, "172.16.0.0/12": true, "192.168.0.0/16": true},
		"internal/netpolicy/resolver.go": {"10.0.0.0/8": true, "172.16.0.0/12": true, "192.168.0.0/16": true},
	}
	allowedGLIntegrations := map[string]bool{
		"internal/config/config.go":   true, // legacy committed target compatibility
		"scripts/diagnose-openwrt.sh": true, // optional vendor metadata only
	}
	forbiddenTopologyFragments := []string{`"br-lan"`, `"eth0"`, `"eth1"`, "network.interface.lan", "network.interface.wan"}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if rel == ".git" || rel == "docs" || rel == "evidence" || rel == "tests" || rel == "node_modules" || rel == "internal/web/dist" || strings.HasPrefix(rel, ".") && rel != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(rel, "_test.go") || !productionTextFile(rel) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, literal := range ipv4LiteralPattern.FindAllString(string(raw), -1) {
			addrText := strings.SplitN(literal, "/", 2)[0]
			addr, parseErr := netip.ParseAddr(addrText)
			if parseErr != nil || !addr.IsPrivate() {
				continue
			}
			if allowedProtocolRanges[rel][literal] {
				continue
			}
			t.Errorf("private network literal %q in production file %s; derive it at runtime or document an explicit protocol-constant exception", literal, rel)
		}
		for _, fragment := range forbiddenTopologyFragments {
			if strings.Contains(string(raw), fragment) {
				t.Errorf("production file %s contains fixed topology fragment %q", rel, fragment)
			}
		}
		if decorativeRawIdentityPattern.Match(raw) {
			t.Errorf("production file %s stores a display mask in a raw ip/mac field", rel)
		}
		if glinetRuntimePattern.Match(raw) && !allowedGLIntegrations[rel] {
			t.Errorf("production file %s contains an unclassified GL.iNet dependency", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func productionTextFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go", ".sh", ".ps1", ".json", ".ts", ".tsx", ".js", ".uci", ".conf", ".html", ".css", ".yaml", ".yml":
		return true
	default:
		return filepath.Ext(path) == "" && strings.HasPrefix(filepath.ToSlash(path), "openwrt/")
	}
}
