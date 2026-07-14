package dataplane

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"router-policy/internal/artifact"
)

type fakeRunner struct {
	calls [][]string
	fail  int
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) error {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.fail > 0 && len(f.calls) == f.fail {
		return errors.New("fake failure")
	}
	return nil
}

func TestApplyIPPlanUsesFixedArguments(t *testing.T) {
	runner := &fakeRunner{}
	plan := artifact.IPPlan{
		DeploymentReady: true,
		Routes: []artifact.IPRoute{
			{Family: "ipv4", Table: 100, Destination: "default", Type: "unicast", Via: "192.0.2.1", Device: "wan"},
			{Family: "ipv6", Table: 100, Destination: "default", Type: "unicast", Via: "2001:db8::1", Device: "wan"},
		},
		Rules: []artifact.RouteProof{{Tag: "direct", Type: "direct", Mark: "0x41", Table: 100, RulePriority: 10010, RequiresIPv4: true, RequiresIPv6: true}},
	}
	if err := ApplyIPPlan(context.Background(), runner, "ip", plan); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"ip", "-4", "route", "replace", "default", "via", "192.0.2.1", "dev", "wan", "table", "100"},
		{"ip", "-6", "route", "replace", "default", "via", "2001:db8::1", "dev", "wan", "table", "100"},
		{"ip", "-4", "rule", "del", "priority", "10010"},
		{"ip", "-4", "rule", "add", "priority", "10010", "fwmark", "0x41", "lookup", "100"},
		{"ip", "-6", "rule", "del", "priority", "10010"},
		{"ip", "-6", "rule", "add", "priority", "10010", "fwmark", "0x41", "lookup", "100"},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("unexpected commands: %#v", runner.calls)
	}
}

func TestApplyIPPlanInstallsIPv6UnreachableFailClosedRoute(t *testing.T) {
	runner := &fakeRunner{}
	plan := artifact.IPPlan{
		DeploymentReady: true,
		Routes: []artifact.IPRoute{
			{Family: "ipv6", Table: 100, Destination: "::/0", Type: "unreachable"},
		},
	}
	if err := ApplyIPPlan(context.Background(), runner, "ip", plan); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"ip", "-6", "route", "replace", "unreachable", "::/0", "table", "100"}}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("IPv6 fail-closed route used unexpected arguments: %#v", runner.calls)
	}
}

func TestApplyIPPlanStopsOnFailure(t *testing.T) {
	runner := &fakeRunner{fail: 1}
	plan := artifact.IPPlan{DeploymentReady: true, Routes: []artifact.IPRoute{{Family: "ipv4", Table: 100, Destination: "default", Type: "unicast", Via: "192.0.2.1", Device: "wan"}}, Rules: []artifact.RouteProof{{Tag: "direct", Type: "direct", Mark: "0x41", Table: 100, RulePriority: 10010, RequiresIPv4: true}}}
	if err := ApplyIPPlan(context.Background(), runner, "ip", plan); err == nil {
		t.Fatal("ip command failure was ignored")
	}
}

func TestApplyIPPlanInstallsExplicitTProxyRules(t *testing.T) {
	runner := &fakeRunner{}
	plan := artifact.IPPlan{
		DeploymentReady: true,
		IPRules: []artifact.IPRule{
			{Family: "ipv4", Priority: 10000, Mark: "0x100", Mask: "0xffffffff", Table: 102, Purpose: "xray_tproxy"},
			{Family: "ipv6", Priority: 10000, Mark: "0x100", Mask: "0xffffffff", Table: 102, Purpose: "xray_tproxy"},
		},
	}
	if err := ApplyIPPlan(context.Background(), runner, "ip", plan); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"ip", "-4", "rule", "del", "priority", "10000"},
		{"ip", "-4", "rule", "add", "priority", "10000", "fwmark", "0x100/0xffffffff", "lookup", "102"},
		{"ip", "-6", "rule", "del", "priority", "10000"},
		{"ip", "-6", "rule", "add", "priority", "10000", "fwmark", "0x100/0xffffffff", "lookup", "102"},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("explicit TPROXY rules were not applied: %#v", runner.calls)
	}
}

func TestApplyIPPlanRejectsUnresolvedDiagnostics(t *testing.T) {
	runner := &fakeRunner{}
	plan := artifact.IPPlan{BlockReason: "network_diagnostics_missing"}
	if err := ApplyIPPlan(context.Background(), runner, "ip", plan); err == nil {
		t.Fatal("unresolved ip plan was applied")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unresolved plan executed commands: %#v", runner.calls)
	}
}

func TestApplyIPPlanDisablesFlowOffloadingWithFixedUCIKeysBeforeRoutes(t *testing.T) {
	runner := &fakeRunner{}
	plan := artifact.IPPlan{
		DeploymentReady: true,
		FlowOffloading:  artifact.FlowOffloadingPlan{Required: true, RequestedPolicy: "disable", Action: "disable", Status: "DISABLE_PLANNED"},
		Routes:          []artifact.IPRoute{{Family: "ipv4", Table: 100, Destination: "default", Type: "unicast", Via: "192.0.2.1", Device: "wan"}},
	}
	if err := ApplyIPPlanWithUCI(context.Background(), runner, "ip", "/sbin/uci", plan); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"/sbin/uci", "set", "firewall.@defaults[0].flow_offloading=0"},
		{"/sbin/uci", "set", "firewall.@defaults[0].flow_offloading_hw=0"},
		{"/sbin/uci", "commit", "firewall"},
		{"ip", "-4", "route", "replace", "default", "via", "192.0.2.1", "dev", "wan", "table", "100"},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("flow offloading commands are not fixed or ordered: %#v", runner.calls)
	}
}

func TestApplyIPPlanStopsBeforeRoutesWhenFlowOffloadingDisableFails(t *testing.T) {
	runner := &fakeRunner{fail: 2}
	plan := artifact.IPPlan{
		DeploymentReady: true,
		FlowOffloading:  artifact.FlowOffloadingPlan{Required: true, RequestedPolicy: "disable", Action: "disable", Status: "DISABLE_PLANNED"},
		Routes:          []artifact.IPRoute{{Family: "ipv4", Table: 100, Destination: "default", Type: "unicast", Via: "192.0.2.1", Device: "wan"}},
	}
	if err := ApplyIPPlanWithUCI(context.Background(), runner, "ip", "uci", plan); err == nil {
		t.Fatal("flow offloading UCI failure was ignored")
	}
	if len(runner.calls) != 2 {
		t.Fatalf("route commands ran after flow offloading failure: %#v", runner.calls)
	}
}
