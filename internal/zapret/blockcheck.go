package zapret

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	MaxBlockcheckReportBytes = 2 << 20
	DefaultBlockcheckTop     = 3
)

type BlockcheckParseOptions struct {
	Queue           uint16
	ProviderVersion string
	BinaryDigest    string
	MaxCandidates   int
}

type BlockcheckCandidate struct {
	Profile     Profile  `json:"profile"`
	Domains     []string `json:"domains"`
	Tests       []string `json:"tests"`
	Occurrences int      `json:"occurrences"`
	FirstLine   int      `json:"first_line"`
}

// BuildBlockcheckCatalog binds the reviewed top candidates to the domain that
// was actually tested. A profile is never promoted to another domain merely
// because it happened to rank well for the same network.
func BuildBlockcheckCatalog(candidates []BlockcheckCandidate, bundleID, domain, failureRoute string) (CatalogFile, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if len(candidates) == 0 || len(candidates) > DefaultBlockcheckTop || domain == "" {
		return CatalogFile{}, errors.New("bounded blockcheck candidates and tested domain are required")
	}
	if failureRoute == "" {
		failureRoute = "drop"
	}
	profiles := make([]Profile, 0, len(candidates))
	fileProfiles := make([]CatalogFileProfile, 0, len(candidates))
	allowedProfiles := make([]string, 0, len(candidates))
	var commonProtocols map[string]Protocol
	for _, candidate := range candidates {
		if !containsBlockcheckDomain(candidate.Domains, domain) {
			continue
		}
		profile := candidate.Profile
		profiles = append(profiles, profile)
		allowedProfiles = append(allowedProfiles, profile.ID)
		fileProfiles = append(fileProfiles, CatalogFileProfile{
			ID: profile.ID, Provider: profile.Provider, ProviderVersion: profile.ProviderVersion,
			BinaryDigest: profile.BinaryDigest, RouteType: profile.RouteType,
			IPFamilies: profile.IPFamilies, Transports: profile.Transports, Ports: profile.Ports,
			Queue: profile.Queue, Safety: profile.Safety, StrategyDigest: profile.StrategyDigest,
			Strategy: string(profile.Strategy),
		})
		supported := blockcheckProfileProtocols(profile)
		if commonProtocols == nil {
			commonProtocols = supported
			continue
		}
		for key := range commonProtocols {
			if _, ok := supported[key]; !ok {
				delete(commonProtocols, key)
			}
		}
	}
	if len(profiles) == 0 {
		return CatalogFile{}, errors.New("no reviewed candidate contains evidence for the tested domain")
	}
	if len(commonProtocols) == 0 {
		return CatalogFile{}, errors.New("blockcheck candidates share no verified protocol scope")
	}
	profileCatalog, err := NewCatalog(profiles)
	if err != nil {
		return CatalogFile{}, err
	}
	protocols := make([]Protocol, 0, len(commonProtocols))
	for _, protocol := range commonProtocols {
		protocols = append(protocols, protocol)
	}
	sort.Slice(protocols, func(i, j int) bool {
		if protocols[i].Transport != protocols[j].Transport {
			return protocols[i].Transport < protocols[j].Transport
		}
		return protocols[i].Port < protocols[j].Port
	})
	bundle := BundleSpec{
		ID: bundleID, Category: "TSPU_RESTRICTED", RequiredDomains: []string{domain},
		Protocols: protocols, IPFamilies: []string{"ipv4"},
		AllowedProfiles: allowedProfiles, FailureRoute: failureRoute,
	}
	if _, err := NewBundleCatalog([]BundleSpec{bundle}, profileCatalog); err != nil {
		return CatalogFile{}, err
	}
	return CatalogFile{Version: 1, Profiles: fileProfiles, Bundles: []BundleSpec{bundle}}, nil
}

type blockcheckAggregate struct {
	core        []string
	transports  map[string]bool
	ports       map[uint16]bool
	domains     map[string]bool
	tests       map[string]bool
	occurrences int
	firstLine   int
}

func containsBlockcheckDomain(domains []string, target string) bool {
	for _, domain := range domains {
		if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(domain), "."), target) {
			return true
		}
	}
	return false
}

func blockcheckProfileProtocols(profile Profile) map[string]Protocol {
	result := map[string]Protocol{}
	for _, transport := range profile.Transports {
		for _, port := range profile.Ports {
			if transport == "udp" && port != 443 {
				continue
			}
			protocol := Protocol{Transport: transport, Port: port}
			result[protocolKey(transport, port)] = protocol
		}
	}
	return result
}

// ParseBlockcheckReport converts upstream blockcheck evidence into a bounded
// candidate set. It never executes or preserves shell syntax: only the same
// reviewed nfqws option allowlist accepted by Profile validation is retained.
func ParseBlockcheckReport(raw []byte, options BlockcheckParseOptions) ([]BlockcheckCandidate, error) {
	if len(raw) == 0 || len(raw) > MaxBlockcheckReportBytes {
		return nil, errors.New("blockcheck report is empty or exceeds 2 MiB")
	}
	if options.Queue == 0 {
		return nil, errors.New("blockcheck candidate queue is required")
	}
	if options.MaxCandidates <= 0 {
		options.MaxCandidates = DefaultBlockcheckTop
	}
	if options.MaxCandidates > DefaultBlockcheckTop {
		options.MaxCandidates = DefaultBlockcheckTop
	}
	aggregates := map[string]*blockcheckAggregate{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 128<<10)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		test, domain, daemon, strategy, ok := parseBlockcheckLine(scanner.Text())
		if !ok || daemon != "nfqws" {
			continue
		}
		transport, port, ok := blockcheckScope(test)
		if !ok {
			continue
		}
		core, ok := normalizeBlockcheckStrategy(strategy)
		if !ok {
			continue
		}
		key := strings.Join(core, "\n")
		item := aggregates[key]
		if item == nil {
			item = &blockcheckAggregate{
				core: core, transports: map[string]bool{}, ports: map[uint16]bool{},
				domains: map[string]bool{}, tests: map[string]bool{}, firstLine: lineNumber,
			}
			aggregates[key] = item
		}
		item.transports[transport] = true
		item.ports[port] = true
		item.domains[domain] = true
		item.tests[test] = true
		item.occurrences++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan blockcheck report: %w", err)
	}

	ranked := make([]*blockcheckAggregate, 0, len(aggregates))
	for _, item := range aggregates {
		ranked = append(ranked, item)
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if len(ranked[i].domains) != len(ranked[j].domains) {
			return len(ranked[i].domains) > len(ranked[j].domains)
		}
		if ranked[i].occurrences != ranked[j].occurrences {
			return ranked[i].occurrences > ranked[j].occurrences
		}
		return ranked[i].firstLine < ranked[j].firstLine
	})

	candidates := make([]BlockcheckCandidate, 0, options.MaxCandidates)
	for _, item := range ranked {
		candidate, err := buildBlockcheckCandidate(item, options)
		if err != nil {
			continue
		}
		candidates = append(candidates, candidate)
		if len(candidates) == options.MaxCandidates {
			break
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("blockcheck report contains no reviewed IPv4 nfqws candidates")
	}
	return candidates, nil
}

func parseBlockcheckLine(line string) (test, domain, daemon string, strategy []string, ok bool) {
	line = strings.TrimSpace(strings.Trim(line, "!"))
	if marker := strings.Index(line, ": working strategy found for ipv4 "); marker >= 0 {
		test = strings.TrimSpace(line[:marker])
		tail := line[marker+len(": working strategy found for ipv4 "):]
		separator := strings.Index(tail, " : ")
		if separator < 1 {
			return "", "", "", nil, false
		}
		domain = strings.Fields(tail[:separator])[0]
		fields := strings.Fields(tail[separator+3:])
		if len(fields) < 2 {
			return "", "", "", nil, false
		}
		return test, domain, fields[0], fields[1:], true
	}
	fields := strings.Fields(line)
	if len(fields) < 6 || fields[1] != "ipv4" {
		return "", "", "", nil, false
	}
	separator := -1
	for index, field := range fields {
		if field == ":" {
			separator = index
			break
		}
	}
	if separator != 3 || separator+2 >= len(fields) {
		return "", "", "", nil, false
	}
	return fields[0], fields[2], fields[separator+1], fields[separator+2:], true
}

func blockcheckScope(test string) (string, uint16, bool) {
	test = strings.ToLower(test)
	switch {
	case strings.Contains(test, "http3") || strings.Contains(test, "quic"):
		return "udp", 443, true
	case strings.Contains(test, "https") || strings.Contains(test, "tls"):
		return "tcp", 443, true
	case strings.Contains(test, "http"):
		return "tcp", 80, true
	default:
		return "", 0, false
	}
}

func normalizeBlockcheckStrategy(fields []string) ([]string, bool) {
	if len(fields) == 0 || len(fields) > maxStrategyLines-2 {
		return nil, false
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if strings.ContainsAny(field, " \t;&|`$\\'\"") {
			return nil, false
		}
		key, value, ok := strings.Cut(field, "=")
		if !ok || key == "--qnum" || key == "--filter-tcp" || key == "--filter-udp" || !allowedOptions[key] || !valuePattern.MatchString(value) {
			return nil, false
		}
		if seen[key] {
			return nil, false
		}
		seen[key] = true
		result = append(result, key+"="+value)
	}
	if !seen["--dpi-desync"] {
		return nil, false
	}
	return result, true
}

func buildBlockcheckCandidate(item *blockcheckAggregate, options BlockcheckParseOptions) (BlockcheckCandidate, error) {
	transports := sortedStringKeys(item.transports)
	ports := sortedPortKeys(item.ports)
	lines := []string{"--qnum=" + strconv.Itoa(int(options.Queue))}
	for _, transport := range transports {
		var scoped []string
		for _, port := range ports {
			if transport == "udp" && port != 443 {
				continue
			}
			scoped = append(scoped, strconv.Itoa(int(port)))
		}
		if len(scoped) == 0 {
			continue
		}
		lines = append(lines, "--filter-"+transport+"="+strings.Join(scoped, ","))
	}
	lines = append(lines, item.core...)
	strategy := []byte(strings.Join(lines, "\n") + "\n")
	digest := Digest(strategy)
	profile := Profile{
		ID:       "blockcheck-" + strings.TrimPrefix(digest, "sha256:")[:12],
		Provider: "nfqws-v1", ProviderVersion: options.ProviderVersion,
		BinaryDigest: options.BinaryDigest, RouteType: "zapret",
		IPFamilies: []string{"ipv4"}, Transports: transports, Ports: ports,
		Queue: options.Queue, Safety: "reviewed", StrategyDigest: digest, Strategy: strategy,
	}
	if _, err := NewCatalog([]Profile{profile}); err != nil {
		return BlockcheckCandidate{}, err
	}
	return BlockcheckCandidate{
		Profile: profile, Domains: sortedStringKeys(item.domains), Tests: sortedStringKeys(item.tests),
		Occurrences: item.occurrences, FirstLine: item.firstLine,
	}, nil
}

func sortedStringKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedPortKeys(values map[uint16]bool) []uint16 {
	result := make([]uint16, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
