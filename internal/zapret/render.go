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
		domains := append(append([]string(nil), bundle.RequiredDomains...), bundle.OptionalDomains...)
		sort.Strings(domains)
		if err := appendScopedStrategy(&output, profile.Strategy, strings.Join(domains, ",")); err != nil {
			return nil, fmt.Errorf("render profile %q for bundle %q: %w", profile.ID, bundle.ID, err)
		}
		if output.Len() > MaxRenderedStrategyBytes {
			return nil, fmt.Errorf("rendered strategy exceeds %d bytes", MaxRenderedStrategyBytes)
		}
	}
	return []byte(output.String()), nil
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
