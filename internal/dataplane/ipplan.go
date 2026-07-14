package dataplane

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"

	"router-policy/internal/artifact"
)

type Runner interface {
	Run(context.Context, string, ...string) error
}

type ExecRunner struct{}

const (
	softwareFlowOffloadUCIKey = "firewall.@defaults[0].flow_offloading"
	hardwareFlowOffloadUCIKey = "firewall.@defaults[0].flow_offloading_hw"
)

func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

func ApplyIPPlan(ctx context.Context, runner Runner, ipBinary string, plan artifact.IPPlan) error {
	return ApplyIPPlanWithUCI(ctx, runner, ipBinary, "uci", plan)
}

func ApplyIPPlanWithUCI(ctx context.Context, runner Runner, ipBinary, uciBinary string, plan artifact.IPPlan) error {
	if runner == nil || ipBinary == "" {
		return fmt.Errorf("runner and ip binary are required")
	}
	if !plan.DeploymentReady {
		return fmt.Errorf("ip plan requires device diagnostics: %s", plan.BlockReason)
	}
	switch plan.FlowOffloading.Action {
	case "", "none":
	case "disable":
		if uciBinary == "" {
			return fmt.Errorf("uci binary is required by flow offloading plan")
		}
		commands := [][]string{
			{"set", softwareFlowOffloadUCIKey + "=0"},
			{"set", hardwareFlowOffloadUCIKey + "=0"},
			{"commit", "firewall"},
		}
		for _, args := range commands {
			if err := runner.Run(ctx, uciBinary, args...); err != nil {
				return fmt.Errorf("apply flow offloading policy: %w", err)
			}
		}
	default:
		return fmt.Errorf("unsupported flow offloading action")
	}
	for _, route := range plan.Routes {
		familyFlag := "-4"
		if route.Family == "ipv6" {
			familyFlag = "-6"
		}
		args := []string{familyFlag, "route", "replace"}
		switch route.Type {
		case "local":
			args = append(args, "local", route.Destination, "dev", route.Device, "table", strconv.Itoa(route.Table))
		case "unreachable":
			args = append(args, "unreachable", route.Destination, "table", strconv.Itoa(route.Table))
		case "unicast":
			args = append(args, route.Destination, "via", route.Via, "dev", route.Device, "table", strconv.Itoa(route.Table))
		default:
			return fmt.Errorf("unsupported %s route type %s", route.Family, route.Type)
		}
		if err := runner.Run(ctx, ipBinary, args...); err != nil {
			return fmt.Errorf("apply %s route table %d: %w", route.Family, route.Table, err)
		}
	}
	if len(plan.IPRules) > 0 {
		for _, rule := range plan.IPRules {
			familyFlag := "-4"
			if rule.Family == "ipv6" {
				familyFlag = "-6"
			} else if rule.Family != "ipv4" {
				return fmt.Errorf("invalid ip rule family for %s", rule.Purpose)
			}
			if rule.Mark == "" || rule.Table <= 0 || rule.Priority <= 0 {
				return fmt.Errorf("incomplete ip rule for %s", rule.Purpose)
			}
			mark := rule.Mark
			if rule.Mask != "" {
				mark += "/" + rule.Mask
			}
			// Touched priorities are project-owned and SnapshotIPState rejects
			// ambiguous/foreign pre-state. Delete by priority so a previous
			// revision with a different mark/table is actually replaced.
			delArgs := []string{familyFlag, "rule", "del", "priority", strconv.Itoa(rule.Priority)}
			_ = runner.Run(ctx, ipBinary, delArgs...)
			addArgs := []string{familyFlag, "rule", "add", "priority", strconv.Itoa(rule.Priority), "fwmark", mark, "lookup", strconv.Itoa(rule.Table)}
			if err := runner.Run(ctx, ipBinary, addArgs...); err != nil {
				return fmt.Errorf("apply %s rule %s: %w", rule.Family, rule.Purpose, err)
			}
		}
		return nil
	}
	for _, rule := range plan.Rules {
		if rule.Type == "drop" || rule.Table == 0 || rule.Mark == "" {
			continue
		}
		priority := strconv.Itoa(rule.RulePriority)
		table := strconv.Itoa(rule.Table)
		delArgs := []string{"rule", "del", "priority", priority}
		addArgs := []string{"rule", "add", "priority", priority, "fwmark", rule.Mark, "lookup", table}
		if rule.RequiresIPv4 {
			_ = runner.Run(ctx, ipBinary, append([]string{"-4"}, delArgs...)...)
			if err := runner.Run(ctx, ipBinary, append([]string{"-4"}, addArgs...)...); err != nil {
				return fmt.Errorf("apply IPv4 rule for %s: %w", rule.Tag, err)
			}
		}
		if rule.RequiresIPv6 {
			_ = runner.Run(ctx, ipBinary, append([]string{"-6"}, delArgs...)...)
			if err := runner.Run(ctx, ipBinary, append([]string{"-6"}, addArgs...)...); err != nil {
				return fmt.Errorf("apply IPv6 rule for %s: %w", rule.Tag, err)
			}
		}
	}
	return nil
}
