package zapret

import (
	"strings"
	"testing"
)

func TestRenderBundleProfilesScopesTwoBundlesDeterministically(t *testing.T) {
	profiles, bundles := renderCatalogs(t, 200, 200)
	assignments := []BundleProfileAssignment{
		{BundleID: "signal", ProfileID: "profile-b"},
		{BundleID: "discord", ProfileID: "profile-a"},
	}
	raw, err := RenderBundleProfiles(bundles, profiles, assignments)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Count(text, "--qnum=200\n") != 1 {
		t.Fatalf("managed queue must be declared once:\n%s", text)
	}
	if strings.Count(text, "--hostlist-domains=discord.com,gateway.discord.gg\n") != 2 {
		t.Fatalf("discord scope was not attached to both transport profiles:\n%s", text)
	}
	if strings.Count(text, "--hostlist-domains=signal.org\n") != 2 {
		t.Fatalf("signal scope was not attached to both transport profiles:\n%s", text)
	}
	if strings.Index(text, "discord.com") > strings.Index(text, "signal.org") {
		t.Fatalf("bundle output is not deterministic:\n%s", text)
	}
	if !strings.Contains(text, "--dpi-desync-ttl=3\n") || !strings.Contains(text, "--dpi-desync-fooling=md5sig\n") {
		t.Fatalf("profile strategies were not preserved:\n%s", text)
	}
}

func TestRenderBundleProfilesRejectsEscapeDuplicateAndQueueMismatch(t *testing.T) {
	profiles, bundles := renderCatalogs(t, 200, 200)
	if _, err := RenderBundleProfiles(bundles, profiles, []BundleProfileAssignment{{BundleID: "discord", ProfileID: "profile-b"}}); err == nil {
		t.Fatal("profile outside bundle allowlist was accepted")
	}
	if _, err := RenderBundleProfiles(bundles, profiles, []BundleProfileAssignment{
		{BundleID: "discord", ProfileID: "profile-a"}, {BundleID: "discord", ProfileID: "profile-a"},
	}); err == nil {
		t.Fatal("duplicate bundle assignment was accepted")
	}
	profiles, bundles = renderCatalogs(t, 200, 201)
	if _, err := RenderBundleProfiles(bundles, profiles, []BundleProfileAssignment{
		{BundleID: "discord", ProfileID: "profile-a"}, {BundleID: "signal", ProfileID: "profile-b"},
	}); err == nil {
		t.Fatal("profiles from different queues were accepted")
	}
}

func renderCatalogs(t *testing.T, firstQueue, secondQueue uint16) (*Catalog, *BundleCatalog) {
	t.Helper()
	strategyA := []byte("--qnum=" + queueString(firstQueue) + "\n--filter-tcp=80\n--dpi-desync=fake,fakedsplit\n--dpi-desync-split-pos=method+2\n--dpi-desync-fooling=md5sig\n--new\n--filter-tcp=443\n--dpi-desync=fake\n--dpi-desync-ttl=3\n--orig-ttl=1\n--orig-mod-start=s1\n--orig-mod-cutoff=d1\n")
	strategyB := []byte("--qnum=" + queueString(secondQueue) + "\n--filter-tcp=80\n--dpi-desync=fake,fakedsplit\n--dpi-desync-split-pos=method+2\n--new\n--filter-tcp=443\n--dpi-desync=fake\n--dpi-desync-ttl=3\n--dpi-desync-fooling=md5sig\n--orig-ttl=1\n--orig-mod-start=s1\n--orig-mod-cutoff=d1\n")
	profiles, err := NewCatalog([]Profile{
		{ID: "profile-a", Provider: "nfqws-v1", ProviderVersion: "72.12", BinaryDigest: Digest([]byte("binary")), RouteType: "zapret", IPFamilies: []string{"ipv4"}, Transports: []string{"tcp"}, Ports: []uint16{80, 443}, Queue: firstQueue, Safety: "reviewed", StrategyDigest: Digest(strategyA), Strategy: strategyA},
		{ID: "profile-b", Provider: "nfqws-v1", ProviderVersion: "72.12", BinaryDigest: Digest([]byte("binary")), RouteType: "zapret", IPFamilies: []string{"ipv4"}, Transports: []string{"tcp"}, Ports: []uint16{80, 443}, Queue: secondQueue, Safety: "reviewed", StrategyDigest: Digest(strategyB), Strategy: strategyB},
	})
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := NewBundleCatalog([]BundleSpec{
		{ID: "discord", Category: "TSPU_RESTRICTED", RequiredDomains: []string{"discord.com"}, OptionalDomains: []string{"gateway.discord.gg"}, Protocols: []Protocol{{Transport: "tcp", Port: 80}, {Transport: "tcp", Port: 443}}, IPFamilies: []string{"ipv4"}, AllowedProfiles: []string{"profile-a"}, FailureRoute: "safe-vless"},
		{ID: "signal", Category: "TSPU_RESTRICTED", RequiredDomains: []string{"signal.org"}, Protocols: []Protocol{{Transport: "tcp", Port: 80}, {Transport: "tcp", Port: 443}}, IPFamilies: []string{"ipv4"}, AllowedProfiles: []string{"profile-b"}, FailureRoute: "safe-vless"},
	}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	return profiles, bundles
}

func queueString(queue uint16) string {
	const digits = "0123456789"
	if queue == 0 {
		return "0"
	}
	var raw [5]byte
	index := len(raw)
	for queue > 0 {
		index--
		raw[index] = digits[queue%10]
		queue /= 10
	}
	return string(raw[index:])
}
