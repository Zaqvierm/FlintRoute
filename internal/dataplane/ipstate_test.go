package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"router-policy/internal/artifact"
)

// stateRunner is an in-memory ip(8) model implementing CommandRunner. It tracks
// route-table routes and policy rules so snapshot/rollback/verify can be proved
// end-to-end without a kernel. applyRunner adapts it to the error-only Runner
// that ApplyIPPlanWithUCI expects, so the same state is mutated by apply.
type stateRunner struct {
	routes          map[string]map[int]map[string]stateRoute // family -> table -> dst -> route
	rules           map[string]map[int]stateRule             // family -> priority -> rule
	disableRuleDel  bool
	disableRouteDel bool
}

type stateRoute struct {
	via, dev, kind string
}
type stateRule struct {
	mark  string
	table int
}

type snapshotRulesRunner struct {
	rules []byte
}

func (s snapshotRulesRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	_, args = (&stateRunner{}).familyOf(args)
	if len(args) >= 5 && args[0] == "-j" && args[1] == "route" && args[2] == "show" && args[3] == "table" {
		return []byte("[]"), nil
	}
	if len(args) >= 3 && args[0] == "-j" && args[1] == "rule" && args[2] == "show" {
		return s.rules, nil
	}
	return nil, errors.New("unexpected snapshot command")
}

func newStateRunner() *stateRunner {
	return &stateRunner{
		routes: map[string]map[int]map[string]stateRoute{},
		rules:  map[string]map[int]stateRule{},
	}
}

func (s *stateRunner) familyOf(args []string) (string, []string) {
	if len(args) > 0 && (args[0] == "-4" || args[0] == "-6") {
		fam := "ipv4"
		if args[0] == "-6" {
			fam = "ipv6"
		}
		return fam, args[1:]
	}
	return "ipv4", args
}

func (s *stateRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	fam, args := s.familyOf(args)
	if len(args) < 2 {
		return nil, errors.New("bad args")
	}
	switch {
	case len(args) >= 5 && args[0] == "-j" && args[1] == "route" && args[2] == "show" && args[3] == "table":
		table := atoiOr(args[4], 0)
		return s.routeJSON(fam, table), nil
	case len(args) >= 3 && args[0] == "-j" && args[1] == "rule" && args[2] == "show":
		return s.ruleJSON(fam), nil
	case args[0] == "route" && args[1] == "replace":
		s.routeReplace(fam, args[2:])
		return nil, nil
	case args[0] == "route" && args[1] == "del":
		if s.disableRouteDel {
			return nil, errors.New("route del disabled")
		}
		s.routeDel(fam, args[2:])
		return nil, nil
	case args[0] == "rule" && args[1] == "replace":
		s.ruleReplace(fam, args[2:])
		return nil, nil
	case args[0] == "rule" && args[1] == "add":
		s.ruleReplace(fam, args[2:])
		return nil, nil
	case args[0] == "rule" && args[1] == "del":
		if s.disableRuleDel {
			return nil, errors.New("rule del disabled")
		}
		s.ruleDel(fam, args[2:])
		return nil, nil
	}
	return nil, errors.New("unhandled ip args")
}

func (s *stateRunner) routeJSON(fam string, table int) []byte {
	out := []map[string]any{}
	for dst, r := range s.routes[fam][table] {
		row := map[string]any{"dst": dst, "gateway": r.via, "dev": r.dev}
		if r.kind == "local" || r.kind == "unreachable" {
			row["type"] = r.kind
		}
		out = append(out, row)
	}
	raw, _ := json.Marshal(out)
	return raw
}

func (s *stateRunner) ruleJSON(fam string) []byte {
	out := []map[string]any{}
	for pri, r := range s.rules[fam] {
		out = append(out, map[string]any{"priority": pri, "fwmark": r.mark, "table": r.table})
	}
	raw, _ := json.Marshal(out)
	return raw
}

func (s *stateRunner) ensureRouteTable(fam string, table int) {
	if s.routes[fam] == nil {
		s.routes[fam] = map[int]map[string]stateRoute{}
	}
	if s.routes[fam][table] == nil {
		s.routes[fam][table] = map[string]stateRoute{}
	}
}

func (s *stateRunner) routeReplace(fam string, args []string) {
	kind := "unicast"
	idx := 0
	if args[0] == "local" || args[0] == "unreachable" {
		kind = args[0]
		idx = 1
	}
	dest := args[idx]
	r := stateRoute{kind: kind}
	for i := idx + 1; i+1 < len(args); i += 2 {
		switch args[i] {
		case "via":
			r.via = args[i+1]
		case "dev":
			r.dev = args[i+1]
		case "table":
			tbl := atoiOr(args[i+1], 0)
			s.ensureRouteTable(fam, tbl)
			s.routes[fam][tbl][dest] = r
		}
	}
}

func (s *stateRunner) routeDel(fam string, args []string) {
	kind := "unicast"
	idx := 0
	if args[0] == "local" || args[0] == "unreachable" {
		kind = args[0]
		idx = 1
	}
	_ = kind
	dest := args[idx]
	for i := idx + 1; i+1 < len(args); i += 2 {
		if args[i] == "table" {
			tbl := atoiOr(args[i+1], 0)
			if s.routes[fam] != nil && s.routes[fam][tbl] != nil {
				delete(s.routes[fam][tbl], dest)
			}
		}
	}
}

func (s *stateRunner) ruleReplace(fam string, args []string) {
	var pri, tbl int
	mark := ""
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "priority":
			pri = atoiOr(args[i+1], 0)
			i++
		case "fwmark":
			mark = args[i+1]
			if j := indexByte(mark, '/'); j >= 0 {
				mark = mark[:j]
			}
			i++
		case "lookup":
			tbl = atoiOr(args[i+1], 0)
			i++
		}
	}
	if s.rules[fam] == nil {
		s.rules[fam] = map[int]stateRule{}
	}
	s.rules[fam][pri] = stateRule{mark: mark, table: tbl}
}

func (s *stateRunner) ruleDel(fam string, args []string) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "priority" {
			pri := atoiOr(args[i+1], 0)
			if s.rules[fam] != nil {
				delete(s.rules[fam], pri)
			}
			return
		}
	}
}

func (s *stateRunner) ruleCount() int {
	n := 0
	for _, m := range s.rules {
		n += len(m)
	}
	return n
}

func (s *stateRunner) routeCount() int {
	n := 0
	for _, tables := range s.routes {
		for _, r := range tables {
			n += len(r)
		}
	}
	return n
}

type applyRunner struct{ inner *stateRunner }

func (a applyRunner) Run(ctx context.Context, name string, args ...string) error {
	_, err := a.inner.Run(ctx, name, args...)
	return err
}

func atoiOr(s string, def int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if s == "" {
		return def
	}
	return n
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func samplePlan() artifact.IPPlan {
	return artifact.IPPlan{
		DeploymentReady: true,
		Routes: []artifact.IPRoute{
			{Family: "ipv4", Table: 100, Destination: "default", Type: "unicast", Via: "192.0.2.1", Device: "wan"},
			{Family: "ipv6", Table: 100, Destination: "::/0", Type: "unreachable"},
		},
		Rules: []artifact.RouteProof{
			{Tag: "direct", Type: "direct", Mark: "0x41", Table: 100, RulePriority: 10010, RequiresIPv4: true, RequiresIPv6: true},
		},
	}
}

func TestRollbackRemovesCreatedRulesAndRoutesFromEmptyPreState(t *testing.T) {
	st := newStateRunner()
	plan := samplePlan()

	pre, err := SnapshotIPState(context.Background(), st, "ip", plan)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(pre.Routes) != 0 || len(pre.Rules) != 0 {
		t.Fatalf("pre-state not empty: %+v", pre)
	}

	if err := ApplyIPPlanWithUCI(context.Background(), applyRunner{st}, "ip", "", plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if st.ruleCount() != 2 || st.routeCount() != 2 {
		t.Fatalf("apply did not create expected state: rules=%d routes=%d", st.ruleCount(), st.routeCount())
	}

	if err := RollbackIPState(context.Background(), st, "ip", plan, pre); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := VerifyIPState(context.Background(), st, "ip", plan, pre); err != nil {
		t.Fatalf("verify after rollback: %v", err)
	}
	if st.ruleCount() != 0 || st.routeCount() != 0 {
		t.Fatalf("rollback left orphans: rules=%d routes=%d", st.ruleCount(), st.routeCount())
	}
}

func TestRollbackRestoresPreStateWhenPriorRevisionExisted(t *testing.T) {
	st := newStateRunner()
	plan := samplePlan()

	// Prior committed revision left a different rule at the same priority and a
	// different default route in table 100.
	st.ensureRouteTable("ipv4", 100)
	st.routes["ipv4"][100]["default"] = stateRoute{via: "198.51.100.1", dev: "eth1", kind: "unicast"}
	if st.rules["ipv4"] == nil {
		st.rules["ipv4"] = map[int]stateRule{}
	}
	st.rules["ipv4"][10010] = stateRule{mark: "0x99", table: 99}

	pre, err := SnapshotIPState(context.Background(), st, "ip", plan)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(pre.Rules) != 1 || pre.Rules[0].Mark != "0x99" || pre.Rules[0].Table != 99 {
		t.Fatalf("pre-state did not capture prior rule: %+v", pre.Rules)
	}
	if len(pre.Routes) != 1 || pre.Routes[0].Via != "198.51.100.1" {
		t.Fatalf("pre-state did not capture prior route: %+v", pre.Routes)
	}

	if err := ApplyIPPlanWithUCI(context.Background(), applyRunner{st}, "ip", "", plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := st.rules["ipv4"][10010]; got.mark != "0x41" || got.table != 100 {
		t.Fatalf("apply did not replace prior rule: %+v", got)
	}

	if err := RollbackIPState(context.Background(), st, "ip", plan, pre); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := VerifyIPState(context.Background(), st, "ip", plan, pre); err != nil {
		t.Fatalf("verify after restore: %v", err)
	}
	if got := st.rules["ipv4"][10010]; got.mark != "0x99" || got.table != 99 {
		t.Fatalf("rollback did not restore prior rule: %+v", got)
	}
	if got := st.routes["ipv4"][100]["default"]; got.via != "198.51.100.1" || got.dev != "eth1" {
		t.Fatalf("rollback did not restore prior route: %+v", got)
	}
}

func TestVerifyDetectsOrphanedRuleWhenRollbackIncomplete(t *testing.T) {
	st := newStateRunner()
	st.disableRuleDel = true
	plan := samplePlan()

	pre, err := SnapshotIPState(context.Background(), st, "ip", plan)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := ApplyIPPlanWithUCI(context.Background(), applyRunner{st}, "ip", "", plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := RollbackIPState(context.Background(), st, "ip", plan, pre); err != nil {
		t.Fatalf("rollback should tolerate failed del: %v", err)
	}
	if err := VerifyIPState(context.Background(), st, "ip", plan, pre); err == nil {
		t.Fatal("verify accepted orphaned rules left by incomplete rollback")
	}
}

func TestSnapshotRejectsForeignRuleAtProjectPriority(t *testing.T) {
	plan := samplePlan()
	runner := snapshotRulesRunner{rules: []byte(`[{"priority":10010,"table":100}]`)}
	if _, err := SnapshotIPState(context.Background(), runner, "ip", plan); err == nil {
		t.Fatal("snapshot accepted a non-fwmark rule at a project-owned priority")
	}
}

func TestSnapshotRejectsDuplicateRulesAtProjectPriority(t *testing.T) {
	plan := samplePlan()
	runner := snapshotRulesRunner{rules: []byte(`[
		{"priority":10010,"fwmark":"0x41","table":100},
		{"priority":10010,"fwmark":"0x42","table":101}
	]`)}
	if _, err := SnapshotIPState(context.Background(), runner, "ip", plan); err == nil {
		t.Fatal("snapshot accepted multiple rules at one project-owned priority")
	}
}

func TestRollbackFailsClosedOnUnrecognizedPreStateRouteType(t *testing.T) {
	plan := samplePlan()
	pre := IPStateSnapshot{
		Routes: []IPStateRoute{{Family: "ipv4", Table: 100, Destination: "default", Type: "throw"}},
	}
	st := newStateRunner()
	if err := RollbackIPState(context.Background(), st, "ip", plan, pre); err == nil {
		t.Fatal("rollback accepted unrecognized pre-state route type")
	}
}

func TestRouteDeleteArgsRejectsUnknownType(t *testing.T) {
	if _, err := routeDeleteArgs("-4", artifact.IPRoute{Type: "throw"}); err == nil {
		t.Fatal("routeDeleteArgs accepted unknown type")
	}
}

func TestTouchedRulesMirrorsApplyDecision(t *testing.T) {
	explicit := artifact.IPPlan{
		DeploymentReady: true,
		IPRules: []artifact.IPRule{
			{Family: "ipv4", Priority: 10000, Mark: "0x100", Mask: "0xffffffff", Table: 102, Purpose: "xray_tproxy"},
			{Family: "ipv6", Priority: 10000, Mark: "0x100", Mask: "0xffffffff", Table: 102, Purpose: "xray_tproxy"},
		},
	}
	got := touchedRules(explicit)
	want := []IPStateRule{
		{Family: "ipv4", Priority: 10000, Mark: "0x100", Table: 102},
		{Family: "ipv6", Priority: 10000, Mark: "0x100", Table: 102},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("explicit touched rules: %+v", got)
	}

	legacy := artifact.IPPlan{
		DeploymentReady: true,
		Rules: []artifact.RouteProof{
			{Tag: "direct", Type: "direct", Mark: "0x41", Table: 100, RulePriority: 10010, RequiresIPv4: true, RequiresIPv6: true},
			{Tag: "drop", Type: "drop", Mark: "0x7f", Table: 0, RulePriority: 20000},
		},
	}
	got = touchedRules(legacy)
	want = []IPStateRule{
		{Family: "ipv4", Priority: 10010, Mark: "0x41", Table: 100},
		{Family: "ipv6", Priority: 10010, Mark: "0x41", Table: 100},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy touched rules: %+v", got)
	}
}
