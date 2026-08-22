package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	hotplugEventMaxBytes = 16 * 1024
	hotplugEventMaxLines = 64
)

func readHotplugEvents(path string) (latest string, count int, digest string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", 0, "", err
	}
	if len(raw) > hotplugEventMaxBytes {
		raw = raw[len(raw)-hotplugEventMaxBytes:]
		if newline := strings.IndexByte(string(raw), '\n'); newline >= 0 {
			raw = raw[newline+1:]
		}
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	if len(lines) > hotplugEventMaxLines {
		lines = lines[len(lines)-hotplugEventMaxLines:]
	}
	if len(lines) > 0 {
		latest = lines[len(lines)-1]
	}
	hash := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return latest, len(lines), hex.EncodeToString(hash[:]), nil
}

func (s *Server) startHotplugObserver(ctx context.Context) {
	path := filepath.Join(s.cfg.Storage.RuntimeDir, "hotplug-events.log")
	if path == "" {
		return
	}
	s.schedulerWG.Add(1)
	go func() {
		defer s.schedulerWG.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				latest, count, digest, err := readHotplugEvents(path)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil || digest == s.hotplugEventDigest {
					continue
				}
				s.hotplugEventDigest = digest
				s.publishEvent(Event{
					Type:       "hotplug.observed",
					Severity:   "info",
					ReasonCode: "owned_drift_observation",
					Details: map[string]any{
						"bounded_event_count": count,
						"latest_event":        latest,
						"mutation":            false,
					},
				})
			}
		}
	}()
}
