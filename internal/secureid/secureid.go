package secureid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// Hex returns a cryptographically random identifier with byteCount bytes of
// entropy. Callers must propagate the error instead of substituting a weak ID.
func Hex(byteCount int) (string, error) {
	return HexFrom(rand.Reader, byteCount)
}

// HexFrom exists so failure paths can be exercised without replacing the
// process-wide crypto/rand reader.
func HexFrom(reader io.Reader, byteCount int) (string, error) {
	if reader == nil {
		return "", fmt.Errorf("secure random reader is required")
	}
	if byteCount <= 0 {
		return "", fmt.Errorf("secure random byte count must be positive")
	}
	raw := make([]byte, byteCount)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return "", fmt.Errorf("read secure random bytes: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
