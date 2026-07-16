package zapret

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-policy/internal/artifact"
)

func TestBindBundleProfilesRebindsVerifiedTransactionManifest(t *testing.T) {
	tx := adapterSwitchTransaction(t)
	if err := os.MkdirAll(tx.ArtifactRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	binding := artifact.Binding{TransactionID: tx.ID, RevisionID: tx.RevisionID, CandidateHash: tx.CandidateHash}
	manifest := artifact.Manifest{Version: artifact.ManifestVersion, Binding: binding, DeploymentReady: true}
	for _, name := range []string{artifact.NFTFile, artifact.DNSMasqFile, artifact.XrayFile, artifact.ZapretFile, artifact.IPPlanFile, artifact.VerifyPlanFile} {
		content := []byte("base " + name + "\n")
		if err := os.WriteFile(filepath.Join(tx.ArtifactRoot, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact.Entry{
			Kind: name, Path: name, SHA256: Digest(content), Bytes: int64(len(content)), Required: true, ProjectOwned: true,
		})
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	tx.ArtifactManifestHash = Digest(raw)
	if err := os.WriteFile(filepath.Join(tx.ArtifactRoot, artifact.ManifestFile), append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tx.ArtifactRoot, artifact.ManifestHashFile), []byte(tx.ArtifactManifestHash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldHash := tx.ArtifactManifestHash
	profiles, bundles := renderCatalogs(t, 200, 200)
	assignments := []BundleProfileAssignment{{BundleID: "signal", ProfileID: "profile-b"}, {BundleID: "discord", ProfileID: "profile-a"}}
	if err := BindBundleProfiles(&tx, bundles, profiles, assignments); err != nil {
		t.Fatal(err)
	}
	if tx.ArtifactManifestHash == oldHash {
		t.Fatal("adaptive config did not change the manifest binding")
	}
	verified, err := artifact.Verify(tx.ArtifactRoot, binding, tx.ArtifactManifestHash)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(verified.Capabilities, "zapret-bundle-profiles") {
		t.Fatalf("adaptive capability is missing: %v", verified.Capabilities)
	}
	config, err := os.ReadFile(filepath.Join(tx.ArtifactRoot, artifact.ZapretFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "--hostlist-domains=discord.com,gateway.discord.gg") ||
		!strings.Contains(string(config), "--hostlist-domains=signal.org") {
		t.Fatalf("bundle scopes are missing from rebound config:\n%s", config)
	}
}

func TestBindBundleProfilesRejectsUnverifiedBaseArtifacts(t *testing.T) {
	tx := adapterSwitchTransaction(t)
	profiles, bundles := renderCatalogs(t, 200, 200)
	err := BindBundleProfiles(&tx, bundles, profiles, []BundleProfileAssignment{{BundleID: "discord", ProfileID: "profile-a"}})
	if err == nil {
		t.Fatal("missing base manifest was accepted")
	}
}
