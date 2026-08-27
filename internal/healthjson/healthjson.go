// Package healthjson provides the narrow, typed parser used by installer
// health checks.  The installer must not infer health by splitting JSON with
// text tools: the response is an API contract, not a line-oriented format.
package healthjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const MaxBytes = 1 << 20

var allowedFields = map[string]struct{}{
	"status":                        {},
	"recovery_status":               {},
	"recovery_commit_phase":         {},
	"active_revision":               {},
	"active_candidate_hash":         {},
	"active_artifact_manifest_hash": {},
}

// ReadField reads one allowlisted string from a health response.  Health
// responses may be either the API envelope (the fields under "data") or the
// bare health object used by small local fixtures.
func ReadField(path, field string) (string, error) {
	if _, ok := allowedFields[field]; !ok {
		return "", fmt.Errorf("health field is not allowlisted: %q", field)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("stat health response: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("health response is not a regular file")
	}
	if info.Size() > MaxBytes {
		return "", fmt.Errorf("health response exceeds %d bytes", MaxBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open health response: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("read health response: %w", err)
	}
	if len(raw) > MaxBytes {
		return "", fmt.Errorf("health response exceeds %d bytes", MaxBytes)
	}

	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&object); err != nil {
		return "", fmt.Errorf("decode health response: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return "", errors.New("health response contains trailing JSON")
		}
		return "", fmt.Errorf("decode trailing health response: %w", err)
	}

	value, ok := object[field]
	if !ok {
		if data, exists := object["data"]; exists {
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(data, &envelope); err != nil {
				return "", fmt.Errorf("decode health data: %w", err)
			}
			value, ok = envelope[field]
		}
	}
	if !ok {
		return "", fmt.Errorf("health field %q is missing", field)
	}

	var result string
	valueDecoder := json.NewDecoder(bytes.NewReader(value))
	if err := valueDecoder.Decode(&result); err != nil {
		return "", fmt.Errorf("health field %q is not a string: %w", field, err)
	}
	if err := valueDecoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return "", fmt.Errorf("health field %q contains trailing JSON", field)
		}
		return "", fmt.Errorf("decode health field %q: %w", field, err)
	}
	return result, nil
}
