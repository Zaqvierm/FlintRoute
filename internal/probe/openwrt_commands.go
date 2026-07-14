package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const maxKernelJSONBytes = 2 << 20

type KernelRoute struct {
	Table     int
	Interface string
}

type KernelRule struct {
	Family   string
	Priority int
	Mark     string
	Table    int
}

type NFTPolicy struct {
	Counter uint64
	Actions map[string]bool
	QUIC    string
}

type OpenWrtCommands interface {
	RouteGet(context.Context, string, string) (KernelRoute, error)
	Rules(context.Context) ([]KernelRule, error)
	HasDefaultRoute(context.Context, string, int) (bool, error)
	NFTPolicy(context.Context, string) (NFTPolicy, error)
	ProcessRunning(context.Context, string) (bool, error)
	ConntrackMark(string, string) (string, error)
}

type ExecOpenWrtCommands struct {
	ipPath        string
	nftPath       string
	pidofPath     string
	conntrackPath string
}

func NewExecOpenWrtCommands() (*ExecOpenWrtCommands, error) {
	ipPath, err := firstExecutable("/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip")
	if err != nil {
		return nil, err
	}
	nftPath, err := firstExecutable("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft")
	if err != nil {
		return nil, err
	}
	pidofPath, err := firstExecutable("/bin/pidof", "/usr/bin/pidof", "/sbin/pidof")
	if err != nil {
		return nil, err
	}
	conntrackPath := "/proc/net/nf_conntrack"
	if _, err := os.Stat(conntrackPath); err != nil {
		conntrackPath = "/proc/net/ip_conntrack"
	}
	return &ExecOpenWrtCommands{ipPath: ipPath, nftPath: nftPath, pidofPath: pidofPath, conntrackPath: conntrackPath}, nil
}

func (c *ExecOpenWrtCommands) RouteGet(ctx context.Context, destination, mark string) (KernelRoute, error) {
	if c == nil || c.ipPath == "" {
		return KernelRoute{}, errors.New("ip_command_unavailable")
	}
	args := []string{"-j", "route", "get", destination}
	if mark != "" {
		args = append(args, "mark", mark)
	}
	raw, err := runBounded(ctx, c.ipPath, args...)
	if err != nil {
		return KernelRoute{}, err
	}
	return parseRouteGet(raw)
}

func (c *ExecOpenWrtCommands) Rules(ctx context.Context) ([]KernelRule, error) {
	if c == nil || c.ipPath == "" {
		return nil, errors.New("ip_command_unavailable")
	}
	var all []KernelRule
	for _, family := range []string{"-4", "-6"} {
		raw, err := runBounded(ctx, c.ipPath, family, "-j", "rule", "show")
		if err != nil {
			return nil, err
		}
		rules, err := parseRules(raw, strings.TrimPrefix(family, "-"))
		if err != nil {
			return nil, err
		}
		all = append(all, rules...)
	}
	return all, nil
}

func (c *ExecOpenWrtCommands) HasDefaultRoute(ctx context.Context, family string, table int) (bool, error) {
	if family != "4" && family != "6" {
		return false, errors.New("invalid_address_family")
	}
	raw, err := runBounded(ctx, c.ipPath, "-"+family, "-j", "route", "show", "table", strconv.Itoa(table), "default")
	if err != nil {
		return false, err
	}
	var routes []map[string]any
	if err := decodeStrictJSON(raw, &routes); err != nil {
		return false, err
	}
	return len(routes) > 0, nil
}

func (c *ExecOpenWrtCommands) NFTPolicy(ctx context.Context, routeTag string) (NFTPolicy, error) {
	if c == nil || c.nftPath == "" {
		return NFTPolicy{}, errors.New("nft_command_unavailable")
	}
	raw, err := runBounded(ctx, c.nftPath, "-j", "list", "table", "inet", "router_policy")
	if err != nil {
		return NFTPolicy{}, err
	}
	return parseNFTPolicy(raw, routeTag)
}

func (c *ExecOpenWrtCommands) ProcessRunning(ctx context.Context, process string) (bool, error) {
	if process != "nfqws" && process != "xray" && process != "tg-ws-proxy" {
		return false, errors.New("process_name_not_allowed")
	}
	cmd := exec.CommandContext(ctx, c.pidofPath, process)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (c *ExecOpenWrtCommands) ConntrackMark(localIP, connectedIP string) (string, error) {
	if localIP == "" || connectedIP == "" {
		return "", errors.New("conntrack_tuple_incomplete")
	}
	raw, err := readBoundedRegular(c.conntrackPath, 8<<20)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "src="+localIP) || !strings.Contains(line, "dst="+connectedIP) {
			continue
		}
		for _, field := range strings.Fields(line) {
			if !strings.HasPrefix(field, "mark=") {
				continue
			}
			value := strings.TrimPrefix(field, "mark=")
			mark, err := parseSocketMark(value)
			if err == nil {
				return formatSocketMark(mark), nil
			}
		}
	}
	return "", errors.New("conntrack_mark_not_found")
}

func runBounded(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedBuffer{Buffer: &stdout, Limit: maxKernelJSONBytes}
	cmd.Stderr = &limitedBuffer{Buffer: &stderr, Limit: 64 << 10}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s failed: %w: %s", filepathBase(path), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

type limitedBuffer struct {
	Buffer *bytes.Buffer
	Limit  int
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	if w.Buffer.Len()+len(p) > w.Limit {
		return 0, errors.New("command_output_limit")
	}
	return w.Buffer.Write(p)
}

func parseRouteGet(raw []byte) (KernelRoute, error) {
	var rows []struct {
		Table any    `json:"table"`
		Dev   string `json:"dev"`
	}
	if err := decodeStrictJSON(raw, &rows); err != nil {
		return KernelRoute{}, err
	}
	if len(rows) != 1 || rows[0].Dev == "" {
		return KernelRoute{}, errors.New("route_get_unexpected_result")
	}
	table, err := integerValue(rows[0].Table)
	if err != nil {
		return KernelRoute{}, err
	}
	return KernelRoute{Table: table, Interface: rows[0].Dev}, nil
}

func parseRules(raw []byte, family string) ([]KernelRule, error) {
	var rows []struct {
		Priority int `json:"priority"`
		Table    any `json:"table"`
		FwMark   any `json:"fwmark"`
	}
	if err := decodeStrictJSON(raw, &rows); err != nil {
		return nil, err
	}
	result := make([]KernelRule, 0, len(rows))
	for _, row := range rows {
		table, err := integerValue(row.Table)
		if err != nil {
			continue
		}
		result = append(result, KernelRule{Family: family, Priority: row.Priority, Mark: markValue(row.FwMark), Table: table})
	}
	return result, nil
}

func parseNFTPolicy(raw []byte, routeTag string) (NFTPolicy, error) {
	var root map[string]any
	if err := decodeStrictJSON(raw, &root); err != nil {
		return NFTPolicy{}, err
	}
	policy := NFTPolicy{Actions: map[string]bool{}}
	needle := "route=" + routeTag
	walkJSON(root, func(value map[string]any) {
		rule, ok := value["rule"].(map[string]any)
		if !ok {
			return
		}
		comment, _ := rule["comment"].(string)
		if !containsToken(comment, needle) {
			return
		}
		for _, token := range strings.Fields(comment) {
			if strings.HasPrefix(token, "action=") {
				policy.Actions[strings.TrimPrefix(token, "action=")] = true
			}
			if strings.HasPrefix(token, "quic=") {
				policy.QUIC = strings.TrimPrefix(token, "quic=")
			}
		}
		expr, _ := rule["expr"].([]any)
		for _, item := range expr {
			entry, _ := item.(map[string]any)
			counter, _ := entry["counter"].(map[string]any)
			packets, err := integerValue(counter["packets"])
			if err == nil && packets > 0 {
				policy.Counter += uint64(packets)
			}
		}
	})
	if len(policy.Actions) == 0 {
		return NFTPolicy{}, errors.New("route_nft_policy_not_found")
	}
	return policy, nil
}

func walkJSON(value any, visit func(map[string]any)) {
	switch typed := value.(type) {
	case map[string]any:
		visit(typed)
		for _, child := range typed {
			walkJSON(child, visit)
		}
	case []any:
		for _, child := range typed {
			walkJSON(child, visit)
		}
	}
}

func decodeStrictJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maxKernelJSONBytes {
		return errors.New("command_json_size_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid command JSON: %w", err)
	}
	if decoder.More() {
		return errors.New("trailing command JSON")
	}
	return nil
}

func integerValue(value any) (int, error) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.Atoi(typed.String())
		return parsed, err
	case float64:
		return int(typed), nil
	case string:
		if typed == "main" {
			return 254, nil
		}
		return strconv.Atoi(typed)
	case nil:
		return 254, nil
	default:
		return 0, errors.New("integer JSON value expected")
	}
}

func markValue(value any) string {
	switch typed := value.(type) {
	case string:
		if mark, err := parseSocketMark(strings.SplitN(typed, "/", 2)[0]); err == nil {
			return formatSocketMark(mark)
		}
	case json.Number:
		if mark, err := parseSocketMark(typed.String()); err == nil {
			return formatSocketMark(mark)
		}
	}
	return ""
}

func containsToken(value, expected string) bool {
	for _, token := range strings.Fields(value) {
		if token == expected {
			return true
		}
	}
	return false
}

func firstExecutable(paths ...string) (string, error) {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return path, nil
		}
	}
	return "", errors.New("required OpenWrt command not found in fixed paths")
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, errors.New("unsafe_or_oversized_file")
	}
	return os.ReadFile(path)
}

func filepathBase(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		return path[i+1:]
	}
	return path
}
