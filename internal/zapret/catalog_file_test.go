package zapret

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCatalogFileBuildsBoundedCatalogs(t *testing.T) {
	strategy := reviewedStrategy
	document := CatalogFile{
		Version: 1,
		Profiles: []CatalogFileProfile{{
			ID: "profile-a", Provider: "nfqws-v1", ProviderVersion: "72.12",
			BinaryDigest: Digest([]byte("binary")), RouteType: "zapret",
			IPFamilies: []string{"ipv4"}, Transports: []string{"tcp"}, Ports: []uint16{80, 443},
			Queue: 200, Safety: "reviewed", StrategyDigest: Digest([]byte(strategy)), Strategy: strategy,
		}},
		Bundles: []BundleSpec{{
			ID: "discord", Category: "TSPU_RESTRICTED", RequiredDomains: []string{"discord.com"},
			Protocols:  []Protocol{{Transport: "tcp", Port: 80}, {Transport: "tcp", Port: 443}},
			IPFamilies: []string{"ipv4"}, AllowedProfiles: []string{"profile-a"}, FailureRoute: "drop",
		}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	profiles, bundles, err := LoadCatalogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if profiles.Len() != 1 || bundles.Len() != 1 {
		t.Fatalf("unexpected catalog sizes: profiles=%d bundles=%d", profiles.Len(), bundles.Len())
	}
	if _, err := RenderBundleProfiles(bundles, profiles, []BundleProfileAssignment{{BundleID: "discord", ProfileID: "profile-a"}}); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCatalogFileRejectsTrailingDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte(`{"version":1}{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadCatalogFile(path); err == nil {
		t.Fatal("trailing JSON document was accepted")
	}
}
