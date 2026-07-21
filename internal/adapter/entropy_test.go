package adapter

import (
	"errors"
	"strings"
	"testing"

	"router-policy/internal/config"
)

func TestNewTransactionFailsWhenEntropyIsUnavailable(t *testing.T) {
	original := secureRandomHex
	secureRandomHex = func(int) (string, error) { return "", errors.New("entropy unavailable") }
	defer func() { secureRandomHex = original }()

	_, err := NewTransaction(&config.Config{Storage: config.Storage{StateDir: t.TempDir()}}, "change", "revision", 1, 2, []byte(`{"version":2}`))
	if err == nil || !strings.Contains(err.Error(), "generate transaction ID") {
		t.Fatalf("expected transaction entropy failure, got %v", err)
	}
}
