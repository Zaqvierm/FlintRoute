package zapret

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const MaxRenderedStrategyBytes = 64 * 1024

type BundleProfileAssignment struct {
	BundleID  string `json:"bundle_id"`
	ProfileID string `json:"profile_id"`
}

// RenderBundleProfiles produces one nfqws config with isolated host scopes.
// Profiles can share an NFQUEUE, but a packet only enters the strategy whose
// host list belongs to its service bundle.
func RenderBundleProfiles(bundles *BundleCatalog, profiles *Catalog, assignments []BundleProfileAssignment) ([]byte, error) {
	if bundles == nil || profiles == nil {
		return nil, errors.New("bundle and profile catalogs are required")
	}
	if len(assignments) == 0 || len(assignments) > MaxBundles {
		return nil, errors.New("bounded bundle profile assignments are required")
	}
	ordered := append([]BundleProfileAssignment(nil), assignments...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].BundleID < ordered[j].BundleID })
	seen := make(map[string]bool, len(ordered))
	var output strings.Builder
	var queue uint16
	var commonBootstrap map[string][]string
	for index, assignment := range ordered {
		if seen[assignment.BundleID] {
			return nil, fmt.Errorf("duplicate bundle assignment %q", assignment.BundleID)
		}
		seen[assignment.BundleID] = true
		bundle, ok := bundles.Lookup(assignment.BundleID)
		if !ok {
			return nil, fmt.Errorf("unknown service bundle %q", assignment.BundleID)
		}
		if !containsString(bundle.AllowedProfiles, assignment.ProfileID) {
			return nil, fmt.Errorf("profile %q is outside bundle %q", assignment.ProfileID, assignment.BundleID)
		}
		profile, ok := profiles.Lookup(assignment.ProfileID)
		if !ok {
			return nil, fmt.Errorf("unknown Zapret profile %q", assignment.ProfileID)
		}
		if index == 0 {
			queue = profile.Queue
			fmt.Fprintf(&output, "--qnum=%d\n", queue)
		} else {
			if profile.Queue != queue {
				return nil, errors.New("bundle profiles must share the managed NFQUEUE")
			}
			output.WriteString("--new\n")
		}
		bootstrap, err := scopedBootstrap(profile.Strategy)
		if err != nil {
			return nil, fmt.Errorf("render profile %q for bundle %q: %w", profile.ID, bundle.ID, err)
		}
		if index == 0 {
			commonBootstrap = bootstrap
		} else if !sameBootstrap(commonBootstrap, bootstrap) {
			return nil, errors.New("bundle profiles require identical pre-hostname bootstrap options")
		}
		domains := append(append([]string(nil), bundle.RequiredDomains...), bundle.OptionalDomains...)
		sort.Strings(domains)
		if err := appendScopedStrategy(&output, profile.Strategy, strings.Join(domains, ",")); err != nil {
			return nil, fmt.Errorf("render profile %q for bundle %q: %w", profile.ID, bundle.ID, err)
		}
		if output.Len() > MaxRenderedStrategyBytes {
			return nil, fmt.Errorf("rendered strategy exceeds %d bytes", MaxRenderedStrategyBytes)
		}
	}
	appendBootstrapProfiles(&output, commonBootstrap)
	return []byte(output.String()), nil
}

var preHostnameOptions = map[string]bool{
	"--orig-ttl": true, "--orig-mod-start": true, "--orig-mod-cutoff": true,
}

// scopedBootstrap extracts the connection setup that must run before nfqws can
// recover HTTP Host or TLS SNI. The same setup is used as an unscoped fallback
// after all bundle profiles; nfqws can then switch to the matching bundle once
// the hostname becomes available.
func scopedBootstrap(strategy []byte) (map[string][]string, error) {
	result := make(map[string][]string)
	currentFilter := ""
	section := 0
	currentFilterSection := 0
	bootstrapSections := make(map[string]int)
	for _, line := range strings.Split(strings.TrimSuffix(string(strategy), "\n"), "\n") {
		if line == "--new" {
			currentFilter = ""
			section++
			continue
		}
		if strings.HasPrefix(line, "--filter-tcp=") || strings.HasPrefix(line, "--filter-udp=") {
			currentFilter = line
			currentFilterSection = section
			continue
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok || !preHostnameOptions[key] {
			continue
		}
		if currentFilter == "" {
			return nil, fmt.Errorf("pre-hostname option %q has no transport filter", line)
		}
		if previousSection, exists := bootstrapSections[currentFilter]; exists && previousSection != currentFilterSection {
			return nil, fmt.Errorf("pre-hostname filter %q is repeated", currentFilter)
		}
		bootstrapSections[currentFilter] = currentFilterSection
		result[currentFilter] = append(result[currentFilter], line)
	}
	return result, nil
}

func sameBootstrap(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for filter, leftOptions := range left {
		rightOptions, ok := right[filter]
		if !ok || len(leftOptions) != len(rightOptions) {
			return false
		}
		for index := range leftOptions {
			if leftOptions[index] != rightOptions[index] {
				return false
			}
		}
	}
	return true
}

func appendBootstrapProfiles(output *strings.Builder, bootstrap map[string][]string) {
	filters := make([]string, 0, len(bootstrap))
	for filter := range bootstrap {
		filters = append(filters, filter)
	}
	sort.Strings(filters)
	for _, filter := range filters {
		output.WriteString("--new\n")
		output.WriteString(filter)
		output.WriteByte('\n')
		for _, option := range bootstrap[filter] {
			output.WriteString(option)
			output.WriteByte('\n')
		}
	}
}

func appendScopedStrategy(output *strings.Builder, strategy []byte, domains string) error {
	if output == nil || domains == "" {
		return errors.New("strategy output and bundle domains are required")
	}
	lines := strings.Split(strings.TrimSuffix(string(strategy), "\n"), "\n")
	filterSeen := false
	for _, line := range lines {
		if strings.HasPrefix(line, "--qnum=") {
			continue
		}
		output.WriteString(line)
		output.WriteByte('\n')
		if strings.HasPrefix(line, "--filter-tcp=") || strings.HasPrefix(line, "--filter-udp=") {
			output.WriteString("--hostlist-domains=")
			output.WriteString(domains)
			output.WriteByte('\n')
			filterSeen = true
		}
	}
	if !filterSeen {
		return errors.New("profile has no transport filter")
	}
	return nil
}
