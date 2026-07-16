package zapret

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"router-policy/internal/tspu"
)

const (
	MaxBundles          = 64
	MaxDomainsPerBundle = 256
	MaxProtocols        = 16
)

type Protocol struct {
	Transport string `json:"transport"`
	Port      uint16 `json:"port"`
}

type BundleSpec struct {
	ID              string     `json:"id"`
	Category        string     `json:"category"`
	RequiredDomains []string   `json:"required_domains"`
	OptionalDomains []string   `json:"optional_domains,omitempty"`
	Protocols       []Protocol `json:"protocols"`
	IPFamilies      []string   `json:"ip_families"`
	AllowedProfiles []string   `json:"allowed_profiles"`
	FailureRoute    string     `json:"failure_route"`
}

type ServiceBundle struct {
	BundleSpec
	Digest string `json:"digest"`
}

type BundleCatalog struct {
	bundles      map[string]ServiceBundle
	domainOwners map[string]string
}

type domainDeclaration struct {
	domain   string
	bundleID string
}

func NewBundleCatalog(specs []BundleSpec, profiles *Catalog) (*BundleCatalog, error) {
	if len(specs) == 0 {
		return nil, errors.New("service bundle catalog must not be empty")
	}
	if len(specs) > MaxBundles {
		return nil, fmt.Errorf("service bundle catalog exceeds %d bundles", MaxBundles)
	}
	if profiles == nil {
		return nil, errors.New("Zapret profile catalog is required")
	}
	catalog := &BundleCatalog{
		bundles:      make(map[string]ServiceBundle, len(specs)),
		domainOwners: make(map[string]string),
	}
	declarations := make([]domainDeclaration, 0)
	for _, raw := range specs {
		bundle, err := normalizeBundle(raw, profiles)
		if err != nil {
			return nil, fmt.Errorf("bundle %q: %w", raw.ID, err)
		}
		if _, exists := catalog.bundles[bundle.ID]; exists {
			return nil, fmt.Errorf("duplicate service bundle %q", bundle.ID)
		}
		catalog.bundles[bundle.ID] = bundle
		for _, domain := range append(append([]string(nil), bundle.RequiredDomains...), bundle.OptionalDomains...) {
			declarations = append(declarations, domainDeclaration{domain: domain, bundleID: bundle.ID})
		}
	}
	sort.Slice(declarations, func(i, j int) bool {
		leftDepth := strings.Count(declarations[i].domain, ".")
		rightDepth := strings.Count(declarations[j].domain, ".")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return declarations[i].domain < declarations[j].domain
	})
	for _, declaration := range declarations {
		if owner, root := catalog.ownerForDomain(declaration.domain); owner != "" && owner != declaration.bundleID {
			return nil, fmt.Errorf("domain %s overlaps bundle %s through %s", declaration.domain, owner, root)
		}
		if owner := catalog.domainOwners[declaration.domain]; owner != "" && owner != declaration.bundleID {
			return nil, fmt.Errorf("domain %s belongs to both %s and %s", declaration.domain, owner, declaration.bundleID)
		}
		catalog.domainOwners[declaration.domain] = declaration.bundleID
	}
	return catalog, nil
}

func (c *BundleCatalog) Lookup(id string) (ServiceBundle, bool) {
	if c == nil {
		return ServiceBundle{}, false
	}
	bundle, ok := c.bundles[id]
	if !ok {
		return ServiceBundle{}, false
	}
	return cloneBundle(bundle), true
}

func (c *BundleCatalog) LookupDomain(domain string) (ServiceBundle, bool) {
	if c == nil {
		return ServiceBundle{}, false
	}
	normalized, err := tspu.NormalizeDomain(domain)
	if err != nil {
		return ServiceBundle{}, false
	}
	owner, _ := c.ownerForDomain(normalized)
	if owner == "" {
		return ServiceBundle{}, false
	}
	return c.Lookup(owner)
}

func (c *BundleCatalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.bundles)
}

func (c *BundleCatalog) ownerForDomain(domain string) (string, string) {
	for current := domain; current != ""; {
		if owner := c.domainOwners[current]; owner != "" {
			return owner, current
		}
		index := strings.IndexByte(current, '.')
		if index < 0 {
			break
		}
		current = current[index+1:]
	}
	return "", ""
}

func normalizeBundle(raw BundleSpec, profiles *Catalog) (ServiceBundle, error) {
	if !profileIDPattern.MatchString(raw.ID) {
		return ServiceBundle{}, errors.New("invalid bundle ID")
	}
	if raw.Category != "TSPU_RESTRICTED" {
		return ServiceBundle{}, errors.New("adaptive Zapret bundle must be TSPU_RESTRICTED")
	}
	if !profileIDPattern.MatchString(raw.FailureRoute) {
		return ServiceBundle{}, errors.New("invalid failure route")
	}
	if len(raw.RequiredDomains) == 0 || len(raw.RequiredDomains)+len(raw.OptionalDomains) > MaxDomainsPerBundle {
		return ServiceBundle{}, errors.New("invalid bundle domain count")
	}
	required, seen, err := normalizeDomains(raw.RequiredDomains, nil)
	if err != nil {
		return ServiceBundle{}, err
	}
	optional, _, err := normalizeDomains(raw.OptionalDomains, seen)
	if err != nil {
		return ServiceBundle{}, err
	}
	protocols, protocolSet, err := normalizeProtocols(raw.Protocols)
	if err != nil {
		return ServiceBundle{}, err
	}
	families, err := normalizeAllowedValues(raw.IPFamilies, map[string]bool{"ipv4": true, "ipv6": true}, "IP family")
	if err != nil {
		return ServiceBundle{}, err
	}
	profileIDs, err := normalizeProfileIDs(raw.AllowedProfiles, profiles, protocolSet, families)
	if err != nil {
		return ServiceBundle{}, err
	}
	normalized := BundleSpec{
		ID: raw.ID, Category: raw.Category, RequiredDomains: required, OptionalDomains: optional,
		Protocols: protocols, IPFamilies: families, AllowedProfiles: profileIDs, FailureRoute: raw.FailureRoute,
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return ServiceBundle{}, fmt.Errorf("marshal service bundle: %w", err)
	}
	return ServiceBundle{BundleSpec: normalized, Digest: Digest(canonical)}, nil
}

func normalizeDomains(values []string, existing map[string]bool) ([]string, map[string]bool, error) {
	seen := make(map[string]bool, len(values))
	for value := range existing {
		seen[value] = true
	}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		domain, err := tspu.NormalizeDomain(value)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid bundle domain %q", value)
		}
		if seen[domain] {
			return nil, nil, fmt.Errorf("duplicate bundle domain %q", domain)
		}
		seen[domain] = true
		normalized = append(normalized, domain)
	}
	sort.Strings(normalized)
	return normalized, seen, nil
}

func normalizeProtocols(values []Protocol) ([]Protocol, map[string]bool, error) {
	if len(values) == 0 || len(values) > MaxProtocols {
		return nil, nil, errors.New("invalid bundle protocol count")
	}
	seen := make(map[string]bool, len(values))
	normalized := append([]Protocol(nil), values...)
	for _, protocol := range normalized {
		if protocol.Transport != "tcp" && protocol.Transport != "udp" || protocol.Port == 0 {
			return nil, nil, errors.New("invalid bundle protocol")
		}
		key := protocolKey(protocol.Transport, protocol.Port)
		if seen[key] {
			return nil, nil, fmt.Errorf("duplicate bundle protocol %s", key)
		}
		seen[key] = true
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Transport != normalized[j].Transport {
			return normalized[i].Transport < normalized[j].Transport
		}
		return normalized[i].Port < normalized[j].Port
	})
	return normalized, seen, nil
}

func normalizeAllowedValues(values []string, allowed map[string]bool, label string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%s list is empty", label)
	}
	seen := make(map[string]bool, len(values))
	result := append([]string(nil), values...)
	for _, value := range result {
		if !allowed[value] || seen[value] {
			return nil, fmt.Errorf("invalid or duplicate %s %q", label, value)
		}
		seen[value] = true
	}
	sort.Strings(result)
	return result, nil
}

func normalizeProfileIDs(values []string, profiles *Catalog, protocols map[string]bool, families []string) ([]string, error) {
	if len(values) == 0 || len(values) > MaxProfiles {
		return nil, errors.New("invalid allowed profile count")
	}
	allowedFamilies := make(map[string]bool, len(families))
	for _, family := range families {
		allowedFamilies[family] = true
	}
	seen := make(map[string]bool, len(values))
	result := append([]string(nil), values...)
	for _, id := range result {
		if seen[id] {
			return nil, fmt.Errorf("duplicate allowed profile %q", id)
		}
		seen[id] = true
		profile, ok := profiles.Lookup(id)
		if !ok {
			return nil, fmt.Errorf("allowed profile %q is not in the catalog", id)
		}
		for _, family := range profile.IPFamilies {
			if !allowedFamilies[family] {
				return nil, fmt.Errorf("profile %s exceeds bundle IP family scope", id)
			}
		}
		for _, transport := range profile.Transports {
			for _, port := range profile.Ports {
				if !protocols[protocolKey(transport, port)] {
					return nil, fmt.Errorf("profile %s exceeds bundle protocol scope", id)
				}
			}
		}
	}
	sort.Strings(result)
	return result, nil
}

func protocolKey(transport string, port uint16) string {
	return fmt.Sprintf("%s/%d", transport, port)
}

func cloneBundle(bundle ServiceBundle) ServiceBundle {
	bundle.RequiredDomains = append([]string(nil), bundle.RequiredDomains...)
	bundle.OptionalDomains = append([]string(nil), bundle.OptionalDomains...)
	bundle.Protocols = append([]Protocol(nil), bundle.Protocols...)
	bundle.IPFamilies = append([]string(nil), bundle.IPFamilies...)
	bundle.AllowedProfiles = append([]string(nil), bundle.AllowedProfiles...)
	return bundle
}
