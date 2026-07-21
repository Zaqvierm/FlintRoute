package secureid

import (
	"errors"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy source unavailable")
}

func TestHexFromRejectsRandomReadFailure(t *testing.T) {
	if _, err := HexFrom(failingReader{}, 16); err == nil {
		t.Fatal("expected secure random read failure")
	}
}

func TestHexFromReturnsRequestedEntropy(t *testing.T) {
	id, err := HexFrom(&repeatingReader{value: 0xab}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if id != "abababababababab" {
		t.Fatalf("unexpected identifier: %q", id)
	}
}

type repeatingReader struct {
	value byte
}

func (r *repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.value
	}
	return len(p), nil
}
