package adapter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"router-policy/internal/config"
	"router-policy/internal/writebudget"
)

// CleanupCommitted removes only heavy transaction files after the committed
// config and last-good snapshot have both been persisted. The small binding
// and status journal remain available for diagnostics and reboot recovery.
func CleanupCommitted(cfg *config.Config, tx Transaction) error {
	if cfg == nil || tx.ID == "" || tx.RevisionID == "" {
		return fmt.Errorf("complete committed transaction identity is required")
	}
	root := filepath.Join(cfg.Storage.StateDir, "transactions", tx.RevisionID, tx.ID)
	if !withinOwnedRoot(root, filepath.Join(cfg.Storage.StateDir, "transactions")) {
		return fmt.Errorf("transaction root is outside the state namespace")
	}
	// Candidate and generated artifacts remain as the minimal reboot-verification
	// journal used by recoverCommittedDataplane. The duplicated pre-apply
	// snapshot and rollback capability are no longer needed after commit.
	targets := []string{tx.CapabilityPath, filepath.Join(root, "snapshot")}
	for _, target := range targets {
		if target == "" || !withinOwnedRoot(target, root) {
			return fmt.Errorf("transaction cleanup target is outside the owned root")
		}
		info, err := os.Lstat(target)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink transaction cleanup target")
		}
		if info.IsDir() {
			if err := os.RemoveAll(target); err != nil {
				return err
			}
		} else if err := os.Remove(target); err != nil {
			return err
		}
		writebudget.RecordDelete("committed transaction cleanup")
	}
	return nil
}

func CleanupObsoleteTransaction(cfg *config.Config, revisionID, transactionID string) error {
	if cfg == nil || revisionID == "" || transactionID == "" {
		return nil
	}
	root := filepath.Join(cfg.Storage.StateDir, "transactions", revisionID, transactionID)
	transactions := filepath.Join(cfg.Storage.StateDir, "transactions")
	if !withinOwnedRoot(root, transactions) {
		return fmt.Errorf("obsolete transaction root is outside the state namespace")
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing ambiguous obsolete transaction root")
	}
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	writebudget.RecordDelete("obsolete transaction cleanup")
	return nil
}

func withinOwnedRoot(path, root string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absRoot, absPath)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
