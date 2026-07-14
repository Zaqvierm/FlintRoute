package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"router-policy/internal/artifact"
)

// CommandRunner executes a command and returns bounded stdout. It is the
// output-capturing counterpart of Runner, used for read-back verification.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecCommandRunner runs commands through os/exec with bounded stdout/stderr.
type ExecCommandRunner struct{}

const maxIPStateJSONBytes = 2 << 20

func (ExecCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedStateBuffer{Buffer: &stdout, Limit: maxIPStateJSONBytes}
	cmd.Stderr = &limitedStateBuffer{Buffer: &stderr, Limit: 64 << 10}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s failed: %w: %s", baseName(name), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

type limitedStateBuffer struct {
	Buffer *bytes.Buffer
	Limit  int
}

func (w *limitedStateBuffer) Write(p []byte) (int, error) {
	if w.Buffer.Len()+len(p) > w.Limit {
		return 0, errors.New("command_output_limit")
	}
	return w.Buffer.Write(p)
}

func baseName(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// IPStateSnapshot is the pre-apply kernel routing state for the route tables and
// policy-rule priorities that a deployment-ready IPPlan touches. It is the
// rollback contract: after rollback, the touched keys must match this snapshot.
type IPStateSnapshot struct {
	Routes []IPStateRoute `json:"routes"`
	Rules  []IPStateRule  `json:"rules"`
}

type IPStateRoute struct {
	Family      string `json:"family"`
	Table       int    `json:"table"`
	Destination string `json:"destination"`
	Type        string `json:"type"`
	Via         string `json:"via,omitempty"`
	Device      string `json:"device,omitempty"`
}

type IPStateRule struct {
	Family   string `json:"family"`
	Priority int    `json:"priority"`
	Mark     string `json:"mark"`
	Table    int    `json:"table"`
}

func familyFlag(family string) (string, error) {
	switch family {
	case "ipv4":
		return "-4", nil
	case "ipv6":
		return "-6", nil
	default:
		return "", fmt.Errorf("invalid ip family %q", family)
	}
}

// touchedRules returns the policy rules that ApplyIPPlanWithUCI would create, in
// the same form ApplyIPPlanWithUCI decides between explicit IPRules and legacy
// RouteProof rules. Rollback must touch exactly these priorities.
func touchedRules(plan artifact.IPPlan) []IPStateRule {
	if len(plan.IPRules) > 0 {
		out := make([]IPStateRule, 0, len(plan.IPRules))
		for _, r := range plan.IPRules {
			if r.Priority <= 0 || r.Table <= 0 || r.Mark == "" {
				continue
			}
			out = append(out, IPStateRule{Family: r.Family, Priority: r.Priority, Mark: r.Mark, Table: r.Table})
		}
		return out
	}
	out := make([]IPStateRule, 0, len(plan.Rules))
	for _, r := range plan.Rules {
		if r.Type == "drop" || r.Table <= 0 || r.Mark == "" || r.RulePriority <= 0 {
			continue
		}
		if r.RequiresIPv4 {
			out = append(out, IPStateRule{Family: "ipv4", Priority: r.RulePriority, Mark: r.Mark, Table: r.Table})
		}
		if r.RequiresIPv6 {
			out = append(out, IPStateRule{Family: "ipv6", Priority: r.RulePriority, Mark: r.Mark, Table: r.Table})
		}
	}
	return out
}

// SnapshotIPState captures the current kernel state for the route tables and
// rule priorities that plan would touch. Fail-closed: any unreadable
// table/priority aborts the snapshot, because a missing pre-state makes a safe
// rollback impossible.
func SnapshotIPState(ctx context.Context, runner CommandRunner, ipBinary string, plan artifact.IPPlan) (IPStateSnapshot, error) {
	var snap IPStateSnapshot
	if runner == nil || ipBinary == "" {
		return snap, errors.New("runner and ip binary are required")
	}

	seenTables := map[string]bool{}
	for _, r := range plan.Routes {
		key := r.Family + ":" + strconv.Itoa(r.Table)
		if seenTables[key] {
			continue
		}
		seenTables[key] = true
		flag, err := familyFlag(r.Family)
		if err != nil {
			return snap, err
		}
		raw, err := runner.Run(ctx, ipBinary, flag, "-j", "route", "show", "table", strconv.Itoa(r.Table))
		if err != nil {
			if strings.Contains(string(raw), "Dump terminated") || strings.Contains(err.Error(), "Dump terminated") {
				continue
			}
			return snap, fmt.Errorf("snapshot %s route table %d: %w", r.Family, r.Table, err)
		}
		rows, err := parseRouteRows(raw)
		if err != nil {
			return snap, fmt.Errorf("parse %s route table %d: %w", r.Family, r.Table, err)
		}
		for _, row := range rows {
			snap.Routes = append(snap.Routes, IPStateRoute{
				Family:      r.Family,
				Table:       r.Table,
				Destination: row.Dst,
				Type:        row.typeKind(),
				Via:         row.Gateway,
				Device:      row.Dev,
			})
		}
	}

	rules := touchedRules(plan)
	prioritiesByFamily := map[string]map[int]bool{}
	for _, r := range rules {
		if prioritiesByFamily[r.Family] == nil {
			prioritiesByFamily[r.Family] = map[int]bool{}
		}
		prioritiesByFamily[r.Family][r.Priority] = true
	}
	for family, priorities := range prioritiesByFamily {
		flag, err := familyFlag(family)
		if err != nil {
			return snap, err
		}
		raw, err := runner.Run(ctx, ipBinary, flag, "-j", "rule", "show")
		if err != nil {
			return snap, fmt.Errorf("snapshot %s rules: %w", family, err)
		}
		rows, err := parseRuleRows(raw)
		if err != nil {
			return snap, fmt.Errorf("parse %s rules: %w", family, err)
		}
		seenPriorities := map[int]bool{}
		for _, row := range rows {
			if !priorities[row.Priority] {
				continue
			}
			if seenPriorities[row.Priority] {
				return snap, fmt.Errorf("snapshot %s rule priority %d: multiple rules are not safely restorable", family, row.Priority)
			}
			seenPriorities[row.Priority] = true
			mark := ruleMarkValue(row.FwMark)
			table := ruleTableInt(row.Table)
			if mark == "" || table <= 0 {
				return snap, fmt.Errorf("snapshot %s rule priority %d: unsupported non-fwmark rule", family, row.Priority)
			}
			snap.Rules = append(snap.Rules, IPStateRule{Family: family, Priority: row.Priority, Mark: mark, Table: table})
		}
	}
	return snap, nil
}

// RollbackIPState removes the route-table routes and policy rules that plan
// created, and restores any that pre-existed from pre. Delete errors are
// non-fatal here: VerifyIPState is the fail-closed authority that detects
// leftovers. Restore errors and unrecognized pre-state shapes are fatal because
// silently rewriting the kernel to an unknown form would be worse than refusing.
func RollbackIPState(ctx context.Context, runner CommandRunner, ipBinary string, plan artifact.IPPlan, pre IPStateSnapshot) error {
	if runner == nil || ipBinary == "" {
		return errors.New("runner and ip binary are required")
	}

	preRoute := map[string]IPStateRoute{}
	for _, r := range pre.Routes {
		preRoute[routeKey(r.Family, r.Table, r.Destination)] = r
	}
	for _, r := range plan.Routes {
		flag, err := familyFlag(r.Family)
		if err != nil {
			return err
		}
		delArgs, err := routeDeleteArgs(flag, r)
		if err != nil {
			return err
		}
		_, _ = runner.Run(ctx, ipBinary, delArgs...)
		if pr, ok := preRoute[routeKey(r.Family, r.Table, r.Destination)]; ok {
			restoreArgs, err := routeReplaceArgs(flag, pr)
			if err != nil {
				return fmt.Errorf("restore %s route table %d: %w", r.Family, r.Table, err)
			}
			if _, err := runner.Run(ctx, ipBinary, restoreArgs...); err != nil {
				return fmt.Errorf("restore %s route table %d: %w", r.Family, r.Table, err)
			}
		}
	}

	preRule := map[string]IPStateRule{}
	for _, r := range pre.Rules {
		key := ruleKey(r.Family, r.Priority)
		if _, exists := preRule[key]; exists {
			return fmt.Errorf("restore %s rule %d: duplicate pre-state", r.Family, r.Priority)
		}
		preRule[key] = r
	}
	for _, r := range touchedRules(plan) {
		flag, err := familyFlag(r.Family)
		if err != nil {
			return err
		}
		_, _ = runner.Run(ctx, ipBinary, flag, "rule", "del", "priority", strconv.Itoa(r.Priority))
		if pr, ok := preRule[ruleKey(r.Family, r.Priority)]; ok {
			if pr.Mark == "" || pr.Table <= 0 {
				return fmt.Errorf("restore %s rule %d: pre-state is not fwmark->lookup", r.Family, r.Priority)
			}
			if _, err := runner.Run(ctx, ipBinary, flag, "rule", "add", "priority", strconv.Itoa(pr.Priority), "fwmark", pr.Mark, "lookup", strconv.Itoa(pr.Table)); err != nil {
				return fmt.Errorf("restore %s rule %d: %w", r.Family, r.Priority, err)
			}
		}
	}
	return nil
}

// VerifyIPState re-snapshots the touched keys and requires them to equal pre.
// Any divergence is reported as ip_state_rollback_incomplete so a rollback that
// leaves orphaned rules/routes can never be mistaken for success.
func VerifyIPState(ctx context.Context, runner CommandRunner, ipBinary string, plan artifact.IPPlan, pre IPStateSnapshot) error {
	cur, err := SnapshotIPState(ctx, runner, ipBinary, plan)
	if err != nil {
		return fmt.Errorf("verify resnapshot: %w", err)
	}
	if !routesEqual(restrictRoutes(cur.Routes, plan), restrictRoutes(pre.Routes, plan)) {
		return errors.New("ip_state_rollback_incomplete: routes differ from pre-apply state")
	}
	if !rulesEqual(restrictRules(cur.Rules, plan), restrictRules(pre.Rules, plan)) {
		return errors.New("ip_state_rollback_incomplete: rules differ from pre-apply state")
	}
	return nil
}

func routeKey(family string, table int, dest string) string {
	return family + ":" + strconv.Itoa(table) + ":" + dest
}

func ruleKey(family string, priority int) string {
	return family + ":" + strconv.Itoa(priority)
}

func routeDeleteArgs(flag string, r artifact.IPRoute) ([]string, error) {
	switch r.Type {
	case "unicast":
		return []string{flag, "route", "del", r.Destination, "via", r.Via, "dev", r.Device, "table", strconv.Itoa(r.Table)}, nil
	case "local":
		return []string{flag, "route", "del", "local", r.Destination, "dev", r.Device, "table", strconv.Itoa(r.Table)}, nil
	case "unreachable":
		return []string{flag, "route", "del", "unreachable", r.Destination, "table", strconv.Itoa(r.Table)}, nil
	default:
		return nil, fmt.Errorf("unsupported route type for delete: %s", r.Type)
	}
}

func routeReplaceArgs(flag string, r IPStateRoute) ([]string, error) {
	switch r.Type {
	case "unicast":
		if r.Via == "" || r.Device == "" {
			return nil, errors.New("unicast pre-state lacks via/device")
		}
		return []string{flag, "route", "replace", r.Destination, "via", r.Via, "dev", r.Device, "table", strconv.Itoa(r.Table)}, nil
	case "local":
		if r.Device == "" {
			return nil, errors.New("local pre-state lacks device")
		}
		return []string{flag, "route", "replace", "local", r.Destination, "dev", r.Device, "table", strconv.Itoa(r.Table)}, nil
	case "unreachable":
		return []string{flag, "route", "replace", "unreachable", r.Destination, "table", strconv.Itoa(r.Table)}, nil
	default:
		return nil, fmt.Errorf("unsupported pre-state route type: %s", r.Type)
	}
}

func restrictRoutes(routes []IPStateRoute, plan artifact.IPPlan) []IPStateRoute {
	allowed := map[string]bool{}
	for _, r := range plan.Routes {
		allowed[routeKey(r.Family, r.Table, r.Destination)] = true
	}
	out := make([]IPStateRoute, 0, len(routes))
	for _, r := range routes {
		if allowed[routeKey(r.Family, r.Table, r.Destination)] {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return routeKey(out[i].Family, out[i].Table, out[i].Destination) < routeKey(out[j].Family, out[j].Table, out[j].Destination)
	})
	return out
}

func restrictRules(rules []IPStateRule, plan artifact.IPPlan) []IPStateRule {
	allowed := map[string]bool{}
	for _, r := range touchedRules(plan) {
		allowed[ruleKey(r.Family, r.Priority)] = true
	}
	out := make([]IPStateRule, 0, len(rules))
	for _, r := range rules {
		if allowed[ruleKey(r.Family, r.Priority)] {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return ruleKey(out[i].Family, out[i].Priority) < ruleKey(out[j].Family, out[j].Priority)
	})
	return out
}

func routesEqual(a, b []IPStateRoute) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func rulesEqual(a, b []IPStateRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type ipRouteRow struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Type    string `json:"type"`
}

func (r ipRouteRow) typeKind() string {
	if r.Type == "local" || r.Type == "unreachable" {
		return r.Type
	}
	return "unicast"
}

type ipRuleRow struct {
	Priority int `json:"priority"`
	Table    any `json:"table"`
	FwMark   any `json:"fwmark"`
}

func parseRouteRows(raw []byte) ([]ipRouteRow, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxIPStateJSONBytes {
		return nil, errors.New("route json size invalid")
	}
	var rows []ipRouteRow
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&rows); err != nil {
		return nil, fmt.Errorf("invalid route json: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing route json")
	}
	return rows, nil
}

func parseRuleRows(raw []byte) ([]ipRuleRow, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxIPStateJSONBytes {
		return nil, errors.New("rule json size invalid")
	}
	var rows []ipRuleRow
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&rows); err != nil {
		return nil, fmt.Errorf("invalid rule json: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing rule json")
	}
	return rows, nil
}

func ruleMarkValue(value any) string {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return ""
		}
		return strings.SplitN(typed, "/", 2)[0]
	case json.Number:
		return typed.String()
	}
	return ""
}

func ruleTableInt(value any) int {
	switch typed := value.(type) {
	case json.Number:
		n, err := strconv.Atoi(typed.String())
		if err != nil {
			return 0
		}
		return n
	case float64:
		return int(typed)
	case string:
		n, err := strconv.Atoi(typed)
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}
