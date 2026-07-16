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
	current, err := Load(path)
	if err == nil {
		previous = &current
	} else if !errors.Is(err, os.ErrNotExist) {
		return Cache{}, fmt.Errorf("load current TSPU cache: %w", err)
	}

	ttl := time.Duration(cfg.Policy.TSPUListUpdateIntervalSeconds) * time.Second
	cache, err := UpdateWithPrevious(ctx, client, cfg.TSPUSources, cfg.Policy.MaxTSPUListBytes, ttl, now, previous)
	if err != nil {
		return cache, err
	}
	if err := Save(path, cache); err != nil {
		return Cache{}, fmt.Errorf("save TSPU cache: %w", err)
	}
	return cache, nil
}
