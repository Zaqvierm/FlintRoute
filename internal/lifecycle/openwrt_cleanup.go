package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	testRoutingTableMin = 30000
	testRoutingTableMax = 30999
)

type OpenWrtResourceExecutor struct {
	Runner CommandRunner
}

func (e OpenWrtResourceExecutor) Cleanup(manifest Manifest, resource Resource, apply bool) ([]string, string, bool, error) {
	if resource.Owner != manifest.Owner || manifest.Owner.Class != OwnerTestRun || manifest.Owner.ID != manifest.RunID {
		return nil, "skip resource", false, errors.New("owner does not match test-run manifest")
	}
	runner := e.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch resource.Kind {
	case ResourceNFTTable:
		return cleanupNFTTable(ctx, runner, manifest.RunID, resource, apply)
	case ResourceIPRule:
		return cleanupIPRule(ctx, runner, resource, apply)
	case ResourceRoute:
		return cleanupRoute(ctx, runner, resource, apply)
	case ResourceListener:
		return verifyListenerReleased(ctx, runner, resource, apply)
	default:
		return nil, "skip resource", false, fmt.Errorf("resource kind %s has no safe OpenWrt cleanup contract", resource.Kind)
	}
}

func cleanupNFTTable(ctx context.Context, runner CommandRunner, runID string, resource Resource, apply bool) ([]string, string, bool, error) {
	family := resource.Family
	if family != "inet" && family != "ip" && family != "ip6" {
		return nil, "skip nft table", false, errors.New("unsupported nft family")
	}
	expected := testNamespace(runID)
	if resource.Table != expected {
		return []string{"owner matches manifest", "nft table namespace mismatch"}, "skip nft table", false, errors.New("nft table is outside the test-run namespace")
	}
	checks := []string{"owner matches manifest", "nft family is allowlisted", "nft table name matches test-run namespace"}
	out, err := runner.Run(ctx, "nft", "list", "table", family, resource.Table)
	if err != nil {
		if commandReportsAbsent(out, err) {
			return checks, "nft table already absent", apply, nil
		}
		return checks, "skip nft table", false, fmt.Errorf("inspect nft table: %w", err)
	}
	if !apply {
		return checks, "delete exact owned nft table", false, nil
	}
	if _, err := runner.Run(ctx, "nft", "delete", "table", family, resource.Table); err != nil {
		return checks, "delete exact owned nft table", false, fmt.Errorf("delete nft table: %w", err)
	}
	return checks, "delete exact owned nft table", true, nil
}

func cleanupIPRule(ctx context.Context, runner CommandRunner, resource Resource, apply bool) ([]string, string, bool, error) {
	family, err := ipFamilyFlag(resource.Family)
	if err != nil {
		return nil, "skip ip rule", false, err
	}
	priority, err := boundedRoutingNumber(resource.Metadata["priority"], "rule priority")
	if err != nil {
		return nil, "skip ip rule", false, err
	}
	table, err := boundedRoutingNumber(resource.Table, "routing table")
	if err != nil {
		return nil, "skip ip rule", false, err
	}
	checks := []string{"owner matches manifest", "IP family is allowlisted", "rule priority is in FlintRoute test range", "routing table is in FlintRoute test range"}
	out, inspectErr := runner.Run(ctx, "ip", family, "rule", "show", "pref", strconv.Itoa(priority))
	if inspectErr != nil {
		return checks, "skip ip rule", false, fmt.Errorf("inspect ip rule: %w", inspectErr)
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return checks, "ip rule already absent", apply, nil
	}
	if !strings.Contains(string(out), "lookup "+strconv.Itoa(table)) {
		return append(checks, "live rule target mismatch"), "skip ip rule", false, errors.New("live IP rule does not match registered table")
	}
	if !apply {
		return checks, "delete exact owned ip rule", false, nil
	}
	if _, err := runner.Run(ctx, "ip", family, "rule", "del", "pref", strconv.Itoa(priority), "table", strconv.Itoa(table)); err != nil {
		return checks, "delete exact owned ip rule", false, fmt.Errorf("delete ip rule: %w", err)
	}
	return checks, "delete exact owned ip rule", true, nil
}

func cleanupRoute(ctx context.Context, runner CommandRunner, resource Resource, apply bool) ([]string, string, bool, error) {
	family, err := ipFamilyFlag(resource.Family)
	if err != nil {
		return nil, "skip route", false, err
	}
	table, err := boundedRoutingNumber(resource.Table, "routing table")
	if err != nil {
		return nil, "skip route", false, err
	}
	ip, network, err := net.ParseCIDR(resource.Address)
	if err != nil || network.String() != resource.Address || (family == "-4" && ip.To4() == nil) || (family == "-6" && ip.To4() != nil) {
		return nil, "skip route", false, errors.New("route address is not a canonical CIDR for its family")
	}
	checks := []string{"owner matches manifest", "IP family is allowlisted", "routing table is in FlintRoute test range", "route prefix is canonical"}
	out, inspectErr := runner.Run(ctx, "ip", family, "route", "show", "table", strconv.Itoa(table), "exact", resource.Address)
	if inspectErr != nil {
		return checks, "skip route", false, fmt.Errorf("inspect route: %w", inspectErr)
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return checks, "route already absent", apply, nil
	}
	if !strings.Contains(string(out), resource.Address) {
		return append(checks, "live route prefix mismatch"), "skip route", false, errors.New("live route does not match registered prefix")
	}
	if !apply {
		return checks, "delete exact owned route", false, nil
	}
	if _, err := runner.Run(ctx, "ip", family, "route", "del", "table", strconv.Itoa(table), resource.Address); err != nil {
		return checks, "delete exact owned route", false, fmt.Errorf("delete route: %w", err)
	}
	return checks, "delete exact owned route", true, nil
}

func verifyListenerReleased(ctx context.Context, runner CommandRunner, resource Resource, apply bool) ([]string, string, bool, error) {
	host, port, err := net.SplitHostPort(resource.Address)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		return nil, "skip listener", false, errors.New("only loopback test listeners are allowlisted")
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return nil, "skip listener", false, errors.New("invalid listener port")
	}
	checks := []string{"owner matches manifest", "listener is loopback-only"}
	out, inspectErr := runner.Run(ctx, "ss", "-H", "-lntup", "sport = :"+port)
	if inspectErr != nil {
		out, inspectErr = runner.Run(ctx, "netstat", "-lntup")
		if inspectErr != nil {
			return checks, "skip listener", false, fmt.Errorf("inspect listener: ss and netstat unavailable")
		}
		if netstatHasListener(out, host, port) {
			return append(checks, "listener still active after process cleanup"), "skip listener", false, errors.New("listener ownership remains ambiguous")
		}
		return checks, "listener already absent", apply, nil
	}
	if len(strings.TrimSpace(string(out))) != 0 {
		return append(checks, "listener still active after process cleanup"), "skip listener", false, errors.New("listener ownership remains ambiguous")
	}
	return checks, "listener already absent", apply, nil
}

func netstatHasListener(output []byte, host, port string) bool {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local := fields[3]
		if strings.HasSuffix(local, ":"+port) && (strings.HasPrefix(local, host+":") || strings.HasPrefix(local, "["+host+"]:")) {
			return true
		}
	}
	return false
}

func testNamespace(runID string) string {
	replacer := strings.NewReplacer("-", "_", ".", "_", ":", "_")
	return "router_policy_test_" + replacer.Replace(runID)
}

func boundedRoutingNumber(value, field string) (int, error) {
	number, err := strconv.Atoi(value)
	if err != nil || number < testRoutingTableMin || number > testRoutingTableMax {
		return 0, fmt.Errorf("%s is outside FlintRoute test range", field)
	}
	return number, nil
}

func ipFamilyFlag(family string) (string, error) {
	switch family {
	case "ipv4", "4", "-4":
		return "-4", nil
	case "ipv6", "6", "-6":
		return "-6", nil
	default:
		return "", errors.New("unsupported IP family")
	}
}

func commandReportsAbsent(output []byte, err error) bool {
	text := strings.ToLower(string(output) + " " + err.Error())
	return strings.Contains(text, "no such file") || strings.Contains(text, "not found")
}
