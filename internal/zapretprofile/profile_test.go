package zapretprofile

import (
	"strings"
	"testing"
)

func tvProfile() Profile {
	return Profile{
		ID:           "tv-q208",
		Scope:        Scope{IPv4: "192.168.0.162"},
		QueueNum:     208,
		Strategy:     StrategyTVFakeMultidisorder,
		Binary:       "/usr/bin/nfqws",
		ActiveConfig: "/etc/router-policy/zapret/profiles/tv-q208.conf",
		InitScript:   "/etc/init.d/router-policy-zapret-tv-q208",
		Rules: []Rule{
			{Protocol: "udp", Ports: []PortRange{{Start: 443, End: 443}}, Verdict: "drop"},
			{Protocol: "tcp", Ports: []PortRange{{Start: 443, End: 443}}, Verdict: "queue", ConntrackFirstPack: 32},
		},
	}
}

func TestTVProfileValidatesAndRendersTypedRules(t *testing.T) {
	profile := tvProfile()
	if err := ValidateProfiles([]Profile{profile}); err != nil {
		t.Fatal(err)
	}
	nft, err := RenderNft("inet", "app_zapret_managed", "gen_1", []Profile{profile})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip saddr 192.168.0.162 udp dport 443 counter drop",
		"ip saddr 192.168.0.162 tcp dport 443 ct original packets 1-32 counter queue flags bypass to 208",
		"profile=tv-q208",
	} {
		if !strings.Contains(nft, want) {
			t.Fatalf("rendered nft missing %q:\n%s", want, nft)
		}
	}
	args, err := RenderNFQWS(profile)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--qnum=208", "--filter-tcp=443", "fake,multidisorder", "1,midsld", "badseq,md5sig"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("rendered nfqws args missing %q: %s", want, joined)
		}
	}
}

func TestProfilesRejectQueueAndSelectorCollisions(t *testing.T) {
	left := tvProfile()
	right := tvProfile()
	right.ID = "tv-q209"
	right.QueueNum = 209
	right.ActiveConfig = "/etc/router-policy/zapret/profiles/tv-q209.conf"
	right.InitScript = "/etc/init.d/router-policy-zapret-tv-q209"
	if err := ValidateProfiles([]Profile{left, right}); err == nil || !strings.Contains(err.Error(), "device selector") {
		t.Fatalf("expected duplicate selector rejection, got %v", err)
	}
	right.Scope = Scope{IPv4: "192.168.0.163"}
	right.QueueNum = left.QueueNum
	if err := ValidateProfiles([]Profile{left, right}); err == nil || !strings.Contains(err.Error(), "queue 208") {
		t.Fatalf("expected duplicate queue rejection, got %v", err)
	}
}

func TestProfileRejectsUnsafePathsAndReservedQueues(t *testing.T) {
	profile := tvProfile()
	profile.QueueNum = 1
	if err := profile.Validate(); err == nil {
		t.Fatal("reserved system queue was accepted")
	}
	profile = tvProfile()
	profile.ActiveConfig = "/tmp/evil.conf"
	if err := profile.Validate(); err == nil {
		t.Fatal("unowned config path was accepted")
	}
	profile = tvProfile()
	profile.Scope = Scope{IPv4: "192.168.0.0/24"}
	if err := profile.Validate(); err == nil {
		t.Fatal("non-host IPv4 selector was accepted")
	}
}

func TestProfileRendererDoesNotAcceptShellFragments(t *testing.T) {
	profile := tvProfile()
	profile.ID = "tv;reboot"
	if err := profile.Validate(); err == nil {
		t.Fatal("shell fragment was accepted as profile id")
	}
	profile = tvProfile()
	profile.Rules[0].Ports[0] = PortRange{Start: 443, End: 70000}
	if _, err := RenderNft("inet", "app_zapret_managed", "gen_1", []Profile{profile}); err == nil {
		t.Fatal("invalid port range was rendered")
	}
}
