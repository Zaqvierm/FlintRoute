package zapret

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"router-policy/internal/adapter"
	"router-policy/internal/artifact"
)

// BindBundleProfiles replaces the generic nfqws candidate with a bundle-scoped
// config and rebinds the artifact manifest before the adapter capability is
// persisted. No active router file is touched here.
func BindBundleProfiles(tx *adapter.Transaction, bundles *BundleCatalog, profiles *Catalog, assignments []BundleProfileAssignment) error {
	if tx == nil || !tx.ArtifactsReady || tx.ArtifactsSimulation || !digestPattern.MatchString(tx.ArtifactManifestHash) {
		return errors.New("deployment-ready adaptive transaction is required")
	}
	binding := artifact.Binding{TransactionID: tx.ID, RevisionID: tx.RevisionID, CandidateHash: tx.CandidateHash}
	manifest, err := artifact.Verify(tx.ArtifactRoot, binding, tx.ArtifactManifestHash)
	if err != nil {
		return fmt.Errorf("verify base artifacts: %w", err)
	}
	rendered, err := RenderBundleProfiles(bundles, profiles, assignments)
	if err != nil {
		return err
	}
	zapretIndex := -1
	for index := range manifest.Artifacts {
		if manifest.Artifacts[index].Path == artifact.ZapretFile {
			zapretIndex = index
			break
		}
	}
	if zapretIndex < 0 {
		return errors.New("Zapret artifact is missing from the transaction")
	}
	if err := writeAdaptiveFile(filepath.Join(tx.ArtifactRoot, artifact.ZapretFile), rendered); err != nil {
		return err
	}
	manifest.Artifacts[zapretIndex].SHA256 = Digest(rendered)
	manifest.Artifacts[zapretIndex].Bytes = int64(len(rendered))
	if !containsString(manifest.Capabilities, "zapret-bundle-profiles") {
		manifest.Capabilities = append(manifest.Capabilities, "zapret-bundle-profiles")
		sort.Strings(manifest.Capabilities)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshal adaptive artifact manifest: %w", err)
	}
	manifestHash := Digest(raw)
	if err := writeAdaptiveFile(filepath.Join(tx.ArtifactRoot, artifact.ManifestFile), append(raw, '\n')); err != nil {
		return err
	}
	if err := writeAdaptiveFile(filepath.Join(tx.ArtifactRoot, artifact.ManifestHashFile), []byte(manifestHash+"\n")); err != nil {
		return err
	}
	tx.ArtifactManifestHash = manifestHash
	if _, err := artifact.Verify(tx.ArtifactRoot, binding, manifestHash); err != nil {
		return fmt.Errorf("verify rebound artifacts: %w", err)
	}
	return nil
}

func writeAdaptiveFile(path string, content []byte) error {
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() {
		return errors.New("adaptive artifact root is not a directory")
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".adaptive-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}
