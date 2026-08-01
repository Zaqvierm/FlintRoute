package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type BaselineVerifier interface {
	Verify(baseline Baseline) ([]BaselineComparison, error)
}

type OpenWrtBaselineVerifier struct {
	Runner CommandRunner
	Now    func() time.Time
}

type baselineCommand struct {
	name         string
	args         []string
	fallbackName string
	fallbackArgs []string
}

var openWrtBaselineCommands = []baselineCommand{
	{name: "ubus", args: []string{"call", "service", "list", `{"name":"router-policy"}`}},
	{name: "ubus", args: []string{"call", "service", "list", `{"name":"router-policy-xray"}`}},
	{name: "ubus", args: []string{"call", "service", "list", `{"name":"router-policy-zapret"}`}},
	{name: "ss", args: []string{"-H", "-lntup"}, fallbackName: "netstat", fallbackArgs: []string{"-lntup"}},
	{name: "nft", args: []string{"list", "tables"}},
	{name: "ip", args: []string{"-4", "rule", "show"}},
	{name: "ip", args: []string{"-6", "rule", "show"}},
	{name: "ip", args: []string{"-4", "route", "show", "table", "all"}},
	{name: "ip", args: []string{"-6", "route", "show", "table", "all"}},
}

var (
	listenerAttributePattern = regexp.MustCompile(`\b(pid|fd)=\d+\b`)
	netstatProcessPattern    = regexp.MustCompile(`\b\d+/(router-policy|xray|nfqws)\b`)
)

func (v OpenWrtBaselineVerifier) Capture() Baseline {
	runner := v.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	baseline := Baseline{CapturedAt: now.Format(time.RFC3339)}
	for _, command := range openWrtBaselineCommands {
		baseline.Checks = append(baseline.Checks, captureBaselineCheck(runner, command))
	}
	return baseline
}

func (v OpenWrtBaselineVerifier) Verify(baseline Baseline) ([]BaselineComparison, error) {
	runner := v.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	if len(baseline.Checks) == 0 {
		return nil, fmt.Errorf("baseline contains no checks")
	}
	commands := make(map[string]baselineCommand, len(openWrtBaselineCommands))
	for _, command := range openWrtBaselineCommands {
		commands[baselineCheckName(command)] = command
	}
	comparisons := make([]BaselineComparison, 0, len(baseline.Checks))
	for _, expected := range baseline.Checks {
		comparison := BaselineComparison{Name: expected.Name, Expected: expected.SHA256}
		command, ok := commands[expected.Name]
		if !ok {
			comparison.Error = "baseline check is not allowlisted"
			comparisons = append(comparisons, comparison)
			continue
		}
		actual := captureBaselineCheck(runner, command)
		comparison.Available = expected.Available && actual.Available
		comparison.Actual = actual.SHA256
		comparison.Matches = comparison.Available && expected.SHA256 != "" && expected.SHA256 == actual.SHA256
		if !actual.Available {
			comparison.Error = actual.Error
		} else if !expected.Available {
			comparison.Error = "baseline check was unavailable before test"
		}
		comparisons = append(comparisons, comparison)
	}
	return comparisons, nil
}

func captureBaselineCheck(runner CommandRunner, command baselineCommand) BaselineCheck {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := BaselineCheck{Name: baselineCheckName(command)}
	out, err := runner.Run(ctx, command.name, command.args...)
	if err != nil && command.fallbackName != "" {
		out, err = runner.Run(ctx, command.fallbackName, command.fallbackArgs...)
	}
	if err != nil {
		result.Error = "command unavailable or failed"
		return result
	}
	normalized := normalizeBaselineOutputFor(command, out)
	sum := sha256.Sum256(normalized)
	result.SHA256 = "sha256:" + hex.EncodeToString(sum[:])
	result.Available = true
	if len(normalized) > 0 {
		result.Lines = bytes.Count(normalized, []byte{'\n'}) + 1
	}
	return result
}

func normalizeBaselineOutputFor(command baselineCommand, raw []byte) []byte {
	if command.name == "ubus" {
		var value any
		if json.Unmarshal(raw, &value) == nil {
			removeVolatileBaselineFields(value)
			if canonical, err := json.Marshal(value); err == nil {
				raw = canonical
			}
		}
	}
	if command.name == "ss" {
		lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
		managed := make([]string, 0, len(lines))
		for _, line := range lines {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "router-policy") || strings.Contains(lower, "xray") || strings.Contains(lower, "nfqws") {
				line = listenerAttributePattern.ReplaceAllString(line, "$1=*")
				line = netstatProcessPattern.ReplaceAllString(line, "*/$1")
				managed = append(managed, line)
			}
		}
		raw = []byte(strings.Join(managed, "\n"))
	}
	return normalizeBaselineOutput(raw)
}

func removeVolatileBaselineFields(value any) {
	switch typed := value.(type) {
	case map[string]any:
		delete(typed, "pid")
		for _, child := range typed {
			removeVolatileBaselineFields(child)
		}
	case []any:
		for _, child := range typed {
			removeVolatileBaselineFields(child)
		}
	}
}

func normalizeBaselineOutput(raw []byte) []byte {
	raw = bytes.TrimSpace(raw)
	var value any
	if len(raw) > 0 && json.Unmarshal(raw, &value) == nil {
		if canonical, err := json.Marshal(value); err == nil {
			return canonical
		}
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
	}
	return []byte(strings.Join(lines, "\n"))
}

func baselineCheckName(command baselineCommand) string {
	return command.name + " " + strings.Join(command.args, " ")
}
