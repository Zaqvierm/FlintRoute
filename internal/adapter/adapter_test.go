package adapter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"router-policy/internal/config"
)

func TestFilesystemTransactionStopsBeforeRealDataPlane(t *testing.T) {
	tmp := t.TempDir()
	cfg := &config.Config{
		Storage: config.Storage{StateDir: filepath.Join(tmp, "state"), RuntimeDir: filepath.Join(tmp, "runtime")},
		OpenWrt: config.OpenWrt{
			FirewallInclude:        filepath.Join(tmp, "etc", "router-policy.nft"),
			DNSMasqInclude:         filepath.Join(tmp, "etc", "router-policy.conf"),
			RollbackTimeoutSeconds: 30,
		},
		Xray: config.Xray{ActiveConfig: filepath.Join(tmp, "xray", "active.json")},
	}
	tx, err := NewTransaction(cfg, "chg_0011223344556677", "rev_2_001122334455", 1, 2, []byte(`{"version":2}`))
	if err != nil {
		t.Fatal(err)
	}
	a := NewFilesystem(cfg)
	for _, step := range []func(context.Context, Transaction) StepResult{
		a.Prepare,
		a.ValidateCandidate,
		a.SnapshotCurrent,
	} {
		res := step(context.Background(), tx)
		if !res.OK {
			t.Fatalf("%s failed: %+v", res.Step, res)
		}
	}
	apply := a.ApplyCandidate(context.Background(), tx)
	if apply.OK || apply.Status != "SKIPPED" {
		t.Fatalf("expected local apply to require a device, got %+v", apply)
	}
	management := a.VerifyManagementPath(context.Background(), tx)
	if management.OK || management.Status != "UNVERIFIED" || management.ManagementVerified {
		t.Fatalf("expected management path to remain unverified, got %+v", management)
	}
	res := a.VerifyDataPlane(context.Background(), tx)
	if res.OK || res.Status != "UNVERIFIED" || res.DataPlaneVerified {
		t.Fatalf("expected local adapter to remain unverified, got %+v", res)
	}
	if _, err := os.Stat(filepath.Join(cfg.Storage.StateDir, "transactions", tx.RevisionID, tx.ID, "snapshot.manifest.json")); err != nil {
		t.Fatal(err)
	}
}
