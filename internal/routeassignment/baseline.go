package routeassignment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"router-policy/internal/config"
)

// VerifyEmptyBaseline is read-only. A fresh baseline has no production
// generation to reconcile. Any residual mapping or overlay is ambiguity,
// not permission to ignore or remove it without a committed binding.
func VerifyEmptyBaseline(cfg *config.Config) error {
	if cfg == nil || len(cfg.Services) != 0 || len(cfg.Overrides) != 0 {
		return errors.New("baseline contains domain assignments without a production generation")
	}
	if !filepath.IsAbs(cfg.Storage.StateDir) || filepath.Clean(cfg.Storage.StateDir) == string(filepath.Separator) {
		return errors.New("baseline state directory is not a bounded absolute path")
	}
	include, err := includePath(cfg)
	if err != nil {
		return err
	}
	for _, path := range []string{
		filepath.Join(cfg.Storage.StateDir, "route-assignments.json"), include,
		filepath.Join(cfg.Storage.StateDir, "last-good", "active-transaction.env"),
		filepath.Join(cfg.Storage.StateDir, "last-good", "transaction.env"),
		filepath.Join(cfg.Storage.StateDir, "last-good", "router-policy-config.json"),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return fmt.Errorf("cannot prove baseline route assignment absence: %w", err)
			}
			return errors.New("baseline has residual route assignment state; recovery is required")
		}
	}
	return nil
}
