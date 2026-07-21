package vpnsub

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWriteFailsWhenEntropyIsUnavailable(t *testing.T) {
	original := secureRandomHex
	secureRandomHex = func(int) (string, error) { return "", errors.New("entropy unavailable") }
	defer func() { secureRandomHex = original }()

	err := writeFileAtomic(filepath.Join(t.TempDir(), "subscription.json"), []byte("{}"), 0o600)
	if err == nil || !strings.Contains(err.Error(), "generate subscription temporary name") {
		t.Fatalf("expected temporary-name entropy failure, got %v", err)
	}
}
