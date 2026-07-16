package zapret

import (
	"strings"
	"testing"
	"time"
)

func TestBundleCatalogKeepsDomainOwnershipIsolated(t *testing.T) {
	profiles := testProfileCatalog(t)
	catalog, err := NewBundleCatalog([]BundleSpec{
		testBundle("discord", []string{"discord.com", "discord.gg"}),
		testBundle("yandex", []string{"yandex.ru"}),
	}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := catalog.LookupDomain("cdn.discord.com")
	if !ok || owner.ID != "discord" {
		t.Fatalf("Discord subdomain owner = %+v ok=%v", owner, ok)
	}
	owner, ok = catalog.LookupDomain("maps.yandex.ru")
	if !ok || owner.ID != "yandex" {
		t.Fatalf("Yandex subdomain owner = %+v ok=%v", owner, ok)
	}
	if _, ok := catalog.LookupDomain("example.net"); ok {
		t.Fatal("unlisted domain inherited a bundle")
	}
}

func TestBundleCatalogRejectsCrossBundleOverlapAndProfileEscape(t *testing.T) {
	profiles := testProfileCatalog(t)
	parent := testBundle("parent", []string{"example.com"})
	child := testBundle("child", []string{"cdn.example.com"})
	if _, err := NewBundleCatalog([]BundleSpec{parent, child}, profiles); err == nil {
		t.Fatal("parent/child ownership overlap was accepted")
	}

	narrow := testBundle("narrow", []string{"narrow.example"})
	narrow.Protocols = []Protocol{{Transport: "tcp", Port: 443}}
	if _, err := NewBundleCatalog([]BundleSpec{narrow}, profiles); err == nil || !strings.Contains(err.Error(), "protocol scope") {
		t.Fatalf("profile protocol escape was accepted: %v", err)
	}
}

func TestBundleCatalogNormalizesDeterministicallyAndReturnsCopies(t *testing.T) {
	profiles := testProfileCatalog(t)
	first := testBundle("discord", []string{"DISCORD.com", "discord.gg"})
	first.OptionalDomains = []string{"media.discord.com"}
	second := first
	second.RequiredDomains = []string{"discord.gg", "discord.com"}
	catalogA, err := NewBundleCatalog([]BundleSpec{first}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	catalogB, err := NewBundleCatalog([]BundleSpec{second}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	bundleA, _ := catalogA.Lookup("discord")
	bundleB, _ := catalogB.Lookup("discord")
	if bundleA.Digest != bundleB.Digest {
		t.Fatalf("equivalent bundles have different digests: %s != %s", bundleA.Digest, bundleB.Digest)
	}
	bundleA.RequiredDomains[0] = "mutated.example"
	again, _ := catalogA.Lookup("discord")
	if again.RequiredDomains[0] == "mutated.example" {
		t.Fatal("bundle catalog returned mutable internal storage")
	}
}

func TestDNSProvenanceBlocksSharedIPForEveryBundle(t *testing.T) {
	provenance := testDNSProvenance(t, 16)
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	first, err := provenance.Observe(testObservation("discord", "discord.com", "203.0.113.10"), now)
	if err != nil || !first.Routable || first.Status != "OWNED" {
		t.Fatalf("first answer was not owned: %+v err=%v", first, err)
	}
	second, err := provenance.Observe(testObservation("yandex", "yandex.ru", "203.0.113.10"), now)
	if err != nil || second.Routable || second.Status != "AMBIGUOUS" {
		t.Fatalf("shared answer was not quarantined: %+v err=%v", second, err)
	}
	if got := provenance.Routable("discord", "ipv4", now); len(got) != 0 {
		t.Fatalf("shared IP leaked into Discord routes: %v", got)
	}
	if got := provenance.Routable("yandex", "ipv4", now); len(got) != 0 {
		t.Fatalf("shared IP leaked into Yandex routes: %v", got)
	}
	conflicts := provenance.Conflicts(now)
	if len(conflicts) != 1 || len(conflicts[0].Owners) != 2 {
		t.Fatalf("shared IP conflict evidence missing: %+v", conflicts)
	}
	for _, resolution := range provenance.Snapshot(now) {
		if resolution.Routable || resolution.Status != "AMBIGUOUS" {
			t.Fatalf("existing answer remained routable after conflict: %+v", resolution)
		}
	}
}

func TestDNSProvenanceExpiresAndPreservesCNAMEEvidence(t *testing.T) {
	provenance := testDNSProvenance(t, 16)
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	observation := testObservation("discord", "media.discord.com", "2001:db8::10")
	observation.CNAMEChain = []string{"edge.discord.com", "cdn.example.net"}
	observation.TTLSeconds = 30
	resolution, err := provenance.Observe(observation, now)
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Answer.CanonicalName != "cdn.example.net" || len(resolution.Answer.CNAMEChain) != 2 || resolution.Answer.Family != "ipv6" {
		t.Fatalf("CNAME provenance was lost: %+v", resolution)
	}
	if got := provenance.Routable("discord", "ipv6", now.Add(29*time.Second)); len(got) != 1 {
		t.Fatalf("fresh DNS answer missing: %v", got)
	}
	if got := provenance.Routable("discord", "ipv6", now.Add(30*time.Second)); len(got) != 0 {
		t.Fatalf("expired DNS answer remained routable: %v", got)
	}
	if snapshot := provenance.Snapshot(now.Add(30 * time.Second)); len(snapshot) != 0 {
		t.Fatalf("expired DNS provenance remained active: %+v", snapshot)
	}
}

func TestDNSProvenanceConflictClearsAfterOtherOwnerExpires(t *testing.T) {
	provenance := testDNSProvenance(t, 16)
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	discord := testObservation("discord", "discord.com", "203.0.113.30")
	discord.TTLSeconds = 300
	yandex := testObservation("yandex", "yandex.ru", "203.0.113.30")
	yandex.TTLSeconds = 30
	if _, err := provenance.Observe(discord, now); err != nil {
		t.Fatal(err)
	}
	if _, err := provenance.Observe(yandex, now); err != nil {
		t.Fatal(err)
	}
	if got := provenance.Routable("discord", "ipv4", now.Add(29*time.Second)); len(got) != 0 {
		t.Fatalf("conflicted IP became routable too early: %v", got)
	}
	if got := provenance.Routable("discord", "ipv4", now.Add(30*time.Second)); len(got) != 1 {
		t.Fatalf("safe owner did not recover after conflict expiry: %v", got)
	}
}

func TestDNSProvenanceRejectsForeignDomainAndBoundsTTL(t *testing.T) {
	provenance := testDNSProvenance(t, 16)
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	foreign := testObservation("discord", "yandex.ru", "203.0.113.20")
	if _, err := provenance.Observe(foreign, now); err == nil {
		t.Fatal("foreign domain was accepted into Discord bundle")
	}
	long := testObservation("discord", "discord.com", "203.0.113.21")
	long.TTLSeconds = uint32((72 * time.Hour) / time.Second)
	resolution, err := provenance.Observe(long, now)
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Answer.EffectiveTTLSeconds != uint32(MaxAnswerTTL/time.Second) || !resolution.Answer.ExpiresAt.Equal(now.Add(MaxAnswerTTL)) {
		t.Fatalf("DNS TTL was not bounded: %+v", resolution.Answer)
	}
}

func TestDNSProvenanceIsBoundedAndRejectsPrivateAnswers(t *testing.T) {
	provenance := testDNSProvenance(t, 1)
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	private := testObservation("discord", "discord.com", "192.168.1.1")
	if _, err := provenance.Observe(private, now); err == nil {
		t.Fatal("private DNS answer was accepted")
	}
	if _, err := provenance.Observe(testObservation("discord", "discord.com", "203.0.113.40"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := provenance.Observe(testObservation("yandex", "yandex.ru", "203.0.113.41"), now); err == nil {
		t.Fatal("DNS provenance capacity was not enforced")
	}
}

func testProfileCatalog(t *testing.T) *Catalog {
	t.Helper()
	profile := testProfile(Digest([]byte("binary")))
	catalog, err := NewCatalog([]Profile{profile})
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func testBundle(id string, domains []string) BundleSpec {
	return BundleSpec{
		ID: id, Category: "TSPU_RESTRICTED", RequiredDomains: domains,
		Protocols:  []Protocol{{Transport: "tcp", Port: 80}, {Transport: "tcp", Port: 443}},
		IPFamilies: []string{"ipv4", "ipv6"}, AllowedProfiles: []string{"zapret-v1-tls-fake-ttl3"},
		FailureRoute: "vless-fallback",
	}
}

func testDNSProvenance(t *testing.T, maxAnswers int) *DNSProvenance {
	t.Helper()
	catalog, err := NewBundleCatalog([]BundleSpec{
		testBundle("discord", []string{"discord.com"}),
		testBundle("yandex", []string{"yandex.ru"}),
	}, testProfileCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	provenance, err := NewDNSProvenance(catalog, maxAnswers)
	if err != nil {
		t.Fatal(err)
	}
	return provenance
}

func testObservation(bundle, domain, address string) DNSObservation {
	return DNSObservation{
		BundleID: bundle, QueryName: domain, Address: address, TTLSeconds: 300,
		RevisionID: "rev_2_001122334455", CandidateHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Source: "dnsmasq",
	}
}
