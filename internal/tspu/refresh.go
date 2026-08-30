package tspu

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"router-policy/internal/config"
)

// Decoding a large persisted domain cache into map[string]Entry temporarily
// consumes several times the JSON size.  On an OpenWrt router that can evict
// the controller (and unrelated management services) even though the file is
// below the on-disk 32 MiB format limit.  Refresh must fail closed before the
// decode when the retained cache exceeds the memory-safe refresh budget.
const maxRefreshExistingCacheBytes = maxCacheBytes / 4

var errOversizedExistingCache = errors.New("existing TSPU cache exceeds refresh memory budget")

// RefreshFile updates a TSPU cache without replacing the last valid cache on
// source, validation, or persistence failure.
func RefreshFile(ctx context.Context, client *http.Client, cfg *config.Config, path string, now time.Time) (Cache, error) {
	if cfg == nil {
		return Cache{}, errors.New("TSPU refresh config is required")
	}
	if path == "" {
		return Cache{}, errors.New("TSPU cache path is required")
	}
	if len(cfg.TSPUSources) == 0 {
		return Cache{}, errors.New("no TSPU sources configured")
	}
	var previous *Cache
	if err := checkRefreshMemoryBudget(path); err != nil {
		if !errors.Is(err, errOversizedExistingCache) {
			return Cache{}, err
		}
		// The old cache is deliberately not decoded: it may be much larger than
		// the bounded in-memory representation. A fresh accepted source can
		// replace it atomically; a failed refresh leaves the old file untouched.
	} else {
		current, loadErr := Load(path)
		if loadErr == nil {
			previous = &current
		} else if !errors.Is(loadErr, os.ErrNotExist) {
			return Cache{}, fmt.Errorf("load current TSPU cache: %w", loadErr)
		}
	}

	ttl := time.Duration(cfg.Policy.TSPUListUpdateIntervalSeconds) * time.Second
	cache, err := UpdateWithPrevious(ctx, client, cfg.TSPUSources, cfg.Policy.MaxTSPUListBytes, ttl, now, previous)
	if err != nil {
		return cache, err
	}
	if err := Save(path, cache); err != nil {
		return Cache{}, fmt.Errorf("save TSPU cache: %w", err)
	}
	persisted, err := Load(path)
	if err != nil {
		return Cache{}, fmt.Errorf("reload TSPU cache: %w", err)
	}
	return persisted, nil
}

func checkRefreshMemoryBudget(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing TSPU cache: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("existing TSPU cache is not a regular file")
	}
	if info.Size() > maxRefreshExistingCacheBytes {
		return fmt.Errorf("%w: %d bytes, above memory-safe limit %d", errOversizedExistingCache, info.Size(), maxRefreshExistingCacheBytes)
	}
	return nil
}
