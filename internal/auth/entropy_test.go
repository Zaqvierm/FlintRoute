package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestCreateSetupTokenFailsWhenEntropyIsUnavailable(t *testing.T) {
	store := testStore(t)
	original := secureRandomHex
	secureRandomHex = func(int) (string, error) { return "", errors.New("entropy unavailable") }
	defer func() { secureRandomHex = original }()

	_, _, err := store.CreateSetupToken()
	if err == nil || !strings.Contains(err.Error(), "generate setup token") {
		t.Fatalf("expected setup token entropy failure, got %v", err)
	}
}
