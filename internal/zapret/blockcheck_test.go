package zapret

import (
	"strings"
	"testing"
)

func TestParseBlockcheckReportReturnsTopThreeReviewedIPv4Candidates(t *testing.T) {
	report := `
!!!!! curl_test_https_tls12: working strategy found for ipv4 alpha.example : nfqws --dpi-desync=fake --dpi-desync-ttl=3 !!!!!
curl_test_https_tls12 ipv4 beta.example : nfqws --dpi-desync=fake --dpi-desync-ttl=3
curl_test_http ipv4 alpha.example : nfqws --dpi-desync=fake --dpi-desync-ttl=3
curl_test_https_tls13 ipv4 alpha.example : nfqws --dpi-desync=split2 --dpi-desync-split-pos=1
curl_test_https_tls13 ipv4 alpha.example : nfqws --dpi-desync=fake --dpi-desync-repeats=2
curl_test_https_tls13 ipv4 alpha.example : nfqws --dpi-desync=fake --dpi-desync-split-seqovl=3
curl_test_https_tls13 ipv4 alpha.example : nfqws --dpi-desync=fake --dpi-desync-ttl=9
`
	candidates, err := ParseBlockcheckReport([]byte(report), BlockcheckParseOptions{
		Queue: 200, ProviderVersion: "72.12", BinaryDigest: "sha256:" + strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 3 {
		t.Fatalf("candidate count=%d", len(candidates))
	}
	first := candidates[0]
	if first.Occurrences != 3 || len(first.Domains) != 2 {
		t.Fatalf("wrong top candidate evidence: %+v", first)
	}
	if got := string(first.Profile.Strategy); !strings.Contains(got, "--filter-tcp=80,443\n") || !strings.Contains(got, "--dpi-desync-ttl=3\n") {
		t.Fatalf("strategy scope was not normalized: %q", got)
	}
}

func TestParseBlockcheckReportRejectsShellAndUnsupportedOptions(t *testing.T) {
	report := `
curl_test_https_tls12 ipv4 alpha.example : nfqws --dpi-desync=fake;reboot
curl_test_https_tls12 ipv4 alpha.example : nfqws --dpi-desync=fake --dpi-desync-fake-tls=/tmp/payload
curl_test_https_tls12 ipv6 alpha.example : nfqws --dpi-desync=fake
curl_test_https_tls12 ipv4 alpha.example : tpws --split-pos=1
`
	_, err := ParseBlockcheckReport([]byte(report), BlockcheckParseOptions{
		Queue: 200, ProviderVersion: "72.12", BinaryDigest: "sha256:" + strings.Repeat("b", 64),
	})
	if err == nil || !strings.Contains(err.Error(), "no reviewed IPv4") {
		t.Fatalf("unsafe report was accepted: %v", err)
	}
}

func TestParseBlockcheckReportIsBounded(t *testing.T) {
	_, err := ParseBlockcheckReport(make([]byte, MaxBlockcheckReportBytes+1), BlockcheckParseOptions{Queue: 200})
	if err == nil {
		t.Fatal("oversized blockcheck report was accepted")
	}
}

func TestBuildBlockcheckCatalogBindsTopThreeToTestedDomain(t *testing.T) {
	report := `
curl_test_https_tls12 ipv4 alpha.example : nfqws --dpi-desync=fake --dpi-desync-ttl=3
curl_test_https_tls13 ipv4 alpha.example : nfqws --dpi-desync=split2 --dpi-desync-split-pos=1
curl_test_https_tls13 ipv4 alpha.example : nfqws --dpi-desync=fake --dpi-desync-repeats=2
curl_test_https_tls13 ipv4 other.example : nfqws --dpi-desync=fake --dpi-desync-ttl=9
`
	candidates, err := ParseBlockcheckReport([]byte(report), BlockcheckParseOptions{
		Queue: 200, ProviderVersion: "72.12", BinaryDigest: "sha256:" + strings.Repeat("c", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := BuildBlockcheckCatalog(candidates, "auto-alpha", "alpha.example", "vless-selected")
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Profiles) != 3 || len(catalog.Bundles) != 1 {
		t.Fatalf("unexpected catalog shape: %+v", catalog)
	}
	bundle := catalog.Bundles[0]
	if len(bundle.RequiredDomains) != 1 || bundle.RequiredDomains[0] != "alpha.example" || len(bundle.AllowedProfiles) != 3 {
		t.Fatalf("catalog escaped tested domain: %+v", bundle)
	}
	if len(bundle.Protocols) != 1 || bundle.Protocols[0] != (Protocol{Transport: "tcp", Port: 443}) {
		t.Fatalf("candidate protocol intersection is wrong: %+v", bundle.Protocols)
	}
}

func TestBuildBlockcheckCatalogRejectsCandidateFromAnotherDomain(t *testing.T) {
	candidate := BlockcheckCandidate{
		Profile: Profile{
			ID: "profile-a", Provider: "nfqws-v1", ProviderVersion: "72.12",
			BinaryDigest: "sha256:" + strings.Repeat("d", 64), RouteType: "zapret",
			IPFamilies: []string{"ipv4"}, Transports: []string{"tcp"}, Ports: []uint16{443},
			Queue: 200, Safety: "reviewed",
			Strategy: []byte("--qnum=200\n--filter-tcp=443\n--dpi-desync=fake\n"),
		},
		Domains: []string{"other.example"},
	}
	candidate.Profile.StrategyDigest = Digest(candidate.Profile.Strategy)
	if _, err := BuildBlockcheckCatalog([]BlockcheckCandidate{candidate}, "auto-alpha", "alpha.example", "drop"); err == nil {
		t.Fatal("candidate evidence was reused for another domain")
	}
}
