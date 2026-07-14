package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ipState struct {
	Routes map[string][]ipStateRoute `json:"routes"` // "family:table" -> routes
	Rules  map[string]ipStateRule    `json:"rules"`  // "family:priority" -> rule
}

type ipStateRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Type    string `json:"type,omitempty"`
}

type ipStateRule struct {
	Mark  string `json:"fwmark"`
	Table int    `json:"table"`
}

func main() {
	name := strings.TrimSuffix(strings.ToLower(filepath.Base(os.Args[0])), ".exe")
	args := os.Args[1:]
	if logPath := os.Getenv("MOCK_OPENWRT_LOG"); logPath != "" {
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(97)
		}
		_, _ = fmt.Fprintf(file, "%s %s\n", name, strings.Join(args, " "))
		_ = file.Close()
	}

	if name == os.Getenv("MOCK_OPENWRT_FAIL_COMMAND") {
		match := os.Getenv("MOCK_OPENWRT_FAIL_MATCH")
		if match == "" || strings.Contains(strings.Join(args, " "), match) {
			os.Exit(42)
		}
	}
	if name == "xray-init" || name == "zapret-init" {
		os.Exit(handleService(name, args))
	}
	if name == "uci" {
		os.Exit(handleUCI(args))
	}
	if name == "ip" {
		os.Exit(handleIP(args))
	}
}

func handleService(name string, args []string) int {
	root := os.Getenv("MOCK_SERVICE_STATE")
	if root == "" {
		return 0
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return 97
	}
	path := filepath.Join(root, name+".state")
	action := ""
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "restart", "start":
		if err := os.WriteFile(path, []byte("running\n"), 0o600); err != nil {
			return 97
		}
		return 0
	case "stop":
		if err := os.WriteFile(path, []byte("stopped\n"), 0o600); err != nil {
			return 97
		}
		return 0
	case "running":
		raw, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(raw)) == "running" {
			return 0
		}
		return 1
	default:
		return 0
	}
}

func handleIP(args []string) int {
	family := "ipv4"
	if len(args) > 0 && (args[0] == "-4" || args[0] == "-6") {
		if args[0] == "-6" {
			family = "ipv6"
		}
		args = args[1:]
	}
	// Non-JSON legacy query used by management verification.
	if len(args) == 3 && args[0] == "route" && args[1] == "show" && args[2] == "default" {
		fmt.Println("default via 192.0.2.1 dev wan")
		return 0
	}
	state, err := loadIPState()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 95
	}
	if len(args) >= 2 && args[0] == "-j" {
		switch {
		case len(args) >= 5 && args[1] == "route" && args[2] == "show" && args[3] == "table":
			table := atoiOr(args[4], 0)
			out := state.Routes[family+":"+itoa(table)]
			if out == nil {
				out = []ipStateRoute{}
			}
			raw, _ := json.Marshal(out)
			fmt.Println(string(raw))
			return 0
		case len(args) >= 3 && args[1] == "rule" && args[2] == "show":
			out := rulesForFamily(state, family)
			raw, _ := json.Marshal(out)
			fmt.Println(string(raw))
			return 0
		}
		return 2
	}
	if len(args) >= 2 {
		switch args[0] {
		case "route":
			if args[1] == "replace" || args[1] == "add" {
				return ipRouteReplace(state, family, args[2:])
			}
			if args[1] == "del" {
				return ipRouteDel(state, family, args[2:])
			}
		case "rule":
			if args[1] == "replace" || args[1] == "add" {
				return ipRuleReplace(state, family, args[2:])
			}
			if args[1] == "del" {
				return ipRuleDel(state, family, args[2:])
			}
		}
	}
	return 2
}

func ipRouteReplace(state *ipState, family string, args []string) int {
	kind := ""
	idx := 0
	if len(args) > 0 && (args[0] == "local" || args[0] == "unreachable") {
		kind = args[0]
		idx = 1
	}
	if idx >= len(args) {
		return 2
	}
	dest := args[idx]
	r := ipStateRoute{Dst: dest, Type: kind}
	table := 0
	for i := idx + 1; i+1 < len(args); i += 2 {
		switch args[i] {
		case "via":
			r.Gateway = args[i+1]
		case "dev":
			r.Dev = args[i+1]
		case "table":
			table = atoiOr(args[i+1], 0)
		}
	}
	if table == 0 {
		return 2
	}
	key := family + ":" + itoa(table)
	if state.Routes == nil {
		state.Routes = map[string][]ipStateRoute{}
	}
	rows := state.Routes[key]
	found := false
	for i := range rows {
		if rows[i].Dst == dest {
			rows[i] = r
			found = true
			break
		}
	}
	if !found {
		rows = append(rows, r)
	}
	state.Routes[key] = rows
	return saveIPState(state)
}

func ipRouteDel(state *ipState, family string, args []string) int {
	idx := 0
	if len(args) > 0 && (args[0] == "local" || args[0] == "unreachable") {
		idx = 1
	}
	if idx >= len(args) {
		return 0
	}
	dest := args[idx]
	table := 0
	for i := idx + 1; i+1 < len(args); i += 2 {
		if args[i] == "table" {
			table = atoiOr(args[i+1], 0)
		}
	}
	key := family + ":" + itoa(table)
	rows := state.Routes[key]
	for i := range rows {
		if rows[i].Dst == dest {
			rows = append(rows[:i], rows[i+1:]...)
			state.Routes[key] = rows
			return saveIPState(state)
		}
	}
	return 0
}

func ipRuleReplace(state *ipState, family string, args []string) int {
	pri, table := 0, 0
	mark := ""
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "priority":
			pri = atoiOr(args[i+1], 0)
			i++
		case "fwmark":
			mark = args[i+1]
			if j := strings.IndexByte(mark, '/'); j >= 0 {
				mark = mark[:j]
			}
			i++
		case "lookup":
			table = atoiOr(args[i+1], 0)
			i++
		}
	}
	if pri <= 0 || table <= 0 {
		return 2
	}
	if state.Rules == nil {
		state.Rules = map[string]ipStateRule{}
	}
	state.Rules[family+":"+itoa(pri)] = ipStateRule{Mark: mark, Table: table}
	return saveIPState(state)
}

func ipRuleDel(state *ipState, family string, args []string) int {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "priority" {
			pri := atoiOr(args[i+1], 0)
			delete(state.Rules, family+":"+itoa(pri))
			return saveIPState(state)
		}
	}
	return 0
}

type ruleRow struct {
	Priority int    `json:"priority"`
	Mark     string `json:"fwmark"`
	Table    int    `json:"table"`
}

func rulesForFamily(state *ipState, family string) []ruleRow {
	out := []ruleRow{}
	for key, r := range state.Rules {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 || parts[0] != family {
			continue
		}
		out = append(out, ruleRow{Priority: atoiOr(parts[1], 0), Mark: r.Mark, Table: r.Table})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

func loadIPState() (*ipState, error) {
	state := &ipState{Routes: map[string][]ipStateRoute{}, Rules: map[string]ipStateRule{}}
	path := os.Getenv("MOCK_IP_STATE")
	if path == "" {
		return state, nil
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return state, nil
	}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, err
	}
	if state.Routes == nil {
		state.Routes = map[string][]ipStateRoute{}
	}
	if state.Rules == nil {
		state.Rules = map[string]ipStateRule{}
	}
	return state, nil
}

func saveIPState(state *ipState) int {
	path := os.Getenv("MOCK_IP_STATE")
	if path == "" {
		return 0
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return 95
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return 95
	}
	if err := os.Rename(tmp, path); err != nil {
		return 95
	}
	return 0
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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func handleUCI(args []string) int {
	path := os.Getenv("MOCK_UCI_STATE")
	if path == "" {
		return 96
	}
	quiet := len(args) > 0 && args[0] == "-q"
	if quiet {
		args = args[1:]
	}
	state, err := loadUCIState(path)
	if err != nil {
		return 95
	}
	if len(args) == 0 {
		return 2
	}
	switch args[0] {
	case "get":
		if len(args) != 2 {
			return 2
		}
		value, ok := state[args[1]]
		if !ok {
			return 1
		}
		fmt.Println(value)
		return 0
	case "set":
		if len(args) != 2 {
			return 2
		}
		parts := strings.SplitN(args[1], "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			return 2
		}
		state[parts[0]] = parts[1]
		if err := saveUCIState(path, state); err != nil {
			return 95
		}
		return 0
	case "delete":
		if len(args) != 2 {
			return 2
		}
		if _, ok := state[args[1]]; !ok && !quiet {
			return 1
		}
		delete(state, args[1])
		if err := saveUCIState(path, state); err != nil {
			return 95
		}
		return 0
	case "commit":
		if len(args) != 2 || args[1] != "firewall" {
			return 2
		}
		return 0
	default:
		return 2
	}
}

func loadUCIState(path string) (map[string]string, error) {
	state := map[string]string{}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) == 2 && parts[0] != "" {
			state[parts[0]] = parts[1]
		}
	}
	return state, nil
}

func saveUCIState(path string, state map[string]string) error {
	keys := make([]string, 0, len(state))
	for key := range state {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var content strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&content, "%s=%s\n", key, state[key])
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
