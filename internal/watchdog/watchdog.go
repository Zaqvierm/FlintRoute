package watchdog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const InhibitSchemaVersion = 1

type Inhibit struct {
	SchemaVersion int       `json:"schema_version"`
	Owner         string    `json:"owner"`
	Reason        string    `json:"reason"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (i Inhibit) Valid(now time.Time) bool {
	return i.SchemaVersion == InhibitSchemaVersion && i.Owner != "" && i.Reason != "" && i.ExpiresAt.After(i.CreatedAt) && now.Before(i.ExpiresAt)
}

func WriteInhibit(path, owner, reason string, now time.Time, lease time.Duration) (Inhibit, error) {
	if path == "" || owner == "" || reason == "" || lease <= 0 || lease > 2*time.Hour {
		return Inhibit{}, fmt.Errorf("invalid watchdog inhibit")
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return Inhibit{}, fmt.Errorf("refusing symlink inhibit target")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Inhibit{}, err
	}
	value := Inhibit{SchemaVersion: InhibitSchemaVersion, Owner: owner, Reason: reason, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(lease)}
	raw, err := json.Marshal(value)
	if err != nil {
		return Inhibit{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Inhibit{}, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".watchdog-inhibit-*")
	if err != nil {
		return Inhibit{}, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return Inhibit{}, err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return Inhibit{}, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return Inhibit{}, err
	}
	if err := tmp.Close(); err != nil {
		return Inhibit{}, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return Inhibit{}, err
	}
	return value, nil
}

func ReadInhibit(path string, now time.Time) (Inhibit, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Inhibit{}, false, nil
	}
	if err != nil {
		return Inhibit{}, false, err
	}
	var value Inhibit
	if err := json.Unmarshal(raw, &value); err != nil {
		return Inhibit{}, false, err
	}
	return value, value.Valid(now.UTC()), nil
}

type Decision struct {
	Action              string `json:"action"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	Reason              string `json:"reason"`
}

type Controller struct {
	StartedAt           time.Time
	StartupGrace        time.Duration
	FailureThreshold    int
	ConsecutiveFailures int
}

func (c *Controller) Observe(now time.Time, healthy, inhibited bool) Decision {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = 3
	}
	if c.StartupGrace <= 0 {
		c.StartupGrace = 90 * time.Second
	}
	if inhibited {
		c.ConsecutiveFailures = 0
		return Decision{Action: "inhibited", Reason: "maintenance lease is active"}
	}
	if healthy {
		c.ConsecutiveFailures = 0
		return Decision{Action: "healthy", Reason: "health endpoint is available"}
	}
	if now.Before(c.StartedAt.Add(c.StartupGrace)) {
		return Decision{Action: "startup-grace", Reason: "control plane is still starting"}
	}
	c.ConsecutiveFailures++
	if c.ConsecutiveFailures < c.FailureThreshold {
		return Decision{Action: "wait", ConsecutiveFailures: c.ConsecutiveFailures, Reason: "failure threshold not reached"}
	}
	c.ConsecutiveFailures = 0
	return Decision{Action: "restart", ConsecutiveFailures: c.FailureThreshold, Reason: "health failure threshold reached"}
}
