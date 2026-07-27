package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"
)

type baselineRunner struct {
	values map[string][]byte
	errors map[string]error
}

func (r *baselineRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + joinArgs(args)
	return r.values[key], r.errors[key]
}

func TestOpenWrtBaselineFallsBackToBusyBoxNetstat(t *testing.T) {
	runner := &baselineRunner{values: map[string][]byte{}, errors: map[string]error{}}
	for _, command := range openWrtBaselineCommands {
		runner.values[baselineCheckName(command)] = []byte("stable\n")
	}
	listeners := openWrtBaselineCommands[3]
	runner.errors[baselineCheckName(listeners)] = errors.New("ss is unavailable")
	fallbackKey := listeners.fallbackName + " " + joinArgs(listeners.fallbackArgs)
	runner.values[fallbackKey] = []byte("tcp 0 0 127.0.0.1:8787 0.0.0.0:* LISTEN 1/router-policy\n")
	verifier := OpenWrtBaselineVerifier{Runner: runner}
	baseline := verifier.Capture()
	if !baseline.Checks[3].Available || baseline.Checks[3].SHA256 == "" {
		t.Fatalf("netstat fallback was not captured: %+v", baseline.Checks[3])
	}
	comparisons, err := verifier.Verify(baseline)
	if err != nil || !comparisons[3].Matches {
		t.Fatalf("netstat fallback was not stable: comparison=%+v err=%v", comparisons[3], err)
	}
}

func TestListenerBaselineIgnoresUnmanagedOpenWrtSockets(t *testing.T) {
	command := openWrtBaselineCommands[3]
	before := []byte("tcp 0 0 127.0.0.1:8787 0.0.0.0:* LISTEN 10/router-policy\ntcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 20/dropbear\n")
	after := []byte("tcp 0 0 127.0.0.1:8787 0.0.0.0:* LISTEN 10/router-policy\ntcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 99/dropbear\n")
	if string(normalizeBaselineOutputFor(command, before)) != string(normalizeBaselineOutputFor(command, after)) {
		t.Fatal("unmanaged listener churn changed the FlintRoute baseline")
	}
	managedDrift := []byte("tcp 0 0 127.0.0.1:8787 0.0.0.0:* LISTEN 11/router-policy\n")
	if string(normalizeBaselineOutputFor(command, before)) == string(normalizeBaselineOutputFor(command, managedDrift)) {
		t.Fatal("managed listener drift was hidden")
	}
}

func TestOpenWrtBaselineUsesHashesAndDetectsDrift(t *testing.T) {
	runner := &baselineRunner{values: map[string][]byte{}}
	for _, command := range openWrtBaselineCommands {
		runner.values[baselineCheckName(command)] = []byte("stable\n")
	}
	verifier := OpenWrtBaselineVerifier{Runner: runner, Now: func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) }}
	baseline := verifier.Capture()
	if len(baseline.Checks) != len(openWrtBaselineCommands) {
		t.Fatalf("incomplete baseline: %+v", baseline)
	}
	for _, check := range baseline.Checks {
		if !check.Available || check.SHA256 == "" || check.Error != "" {
			t.Fatalf("baseline leaked or omitted evidence: %+v", check)
		}
	}
	comparisons, err := verifier.Verify(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, comparison := range comparisons {
		if !comparison.Matches {
			t.Fatalf("unchanged baseline did not match: %+v", comparison)
		}
	}
	drifted := openWrtBaselineCommands[len(openWrtBaselineCommands)-1]
	runner.values[baselineCheckName(drifted)] = []byte("changed\n")
	comparisons, err = verifier.Verify(baseline)
	if err != nil || comparisons[len(comparisons)-1].Matches {
		t.Fatalf("baseline drift was not detected: comparisons=%+v err=%v", comparisons, err)
	}
}

func joinArgs(args []string) string {
	result := ""
	for index, arg := range args {
		if index > 0 {
			result += " "
		}
		result += arg
	}
	return result
}
