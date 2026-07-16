package zapret

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"sync"
	"time"

	"router-policy/internal/tspu"
)

const (
	MaxDNSAnswers = 4096
	MaxCNAMEChain = 8
	MaxAnswerTTL  = 24 * time.Hour
)

var revisionPattern = regexp.MustCompile(`^rev_[A-Za-z0-9][A-Za-z0-9._-]{0,119}$`)

type DNSObservation struct {
	BundleID      string
	QueryName     string
	CNAMEChain    []string
	Address       string
	TTLSeconds    uint32
	RevisionID    string
	CandidateHash string
	Source        string
}

type DNSAnswer struct {
	BundleID            string    `json:"bundle_id"`
	QueryName           string    `json:"query_name"`
	CanonicalName       string    `json:"canonical_name"`
	CNAMEChain          []string  `json:"cname_chain,omitempty"`
	Address             string    `json:"address"`
	Family              string    `json:"family"`
	OriginalTTLSeconds  uint32    `json:"original_ttl_seconds"`
	EffectiveTTLSeconds uint32    `json:"effective_ttl_seconds"`
	ObservedAt          time.Time `json:"observed_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	RevisionID          string    `json:"revision_id"`
	CandidateHash       string    `json:"candidate_hash"`
	Source              string    `json:"source"`
}

type DNSResolution struct {
	Answer   DNSAnswer `json:"answer"`
	Status   string    `json:"status"`
	Owners   []string  `json:"owners"`
	Routable bool      `json:"routable"`
}

type DNSConflict struct {
	Address string   `json:"address"`
	Family  string   `json:"family"`
	Owners  []string `json:"owners"`
}

type DNSProvenance struct {
	mu         sync.Mutex
	catalog    *BundleCatalog
	maxAnswers int
	answers    map[string]DNSAnswer
}

func NewDNSProvenance(catalog *BundleCatalog, maxAnswers int) (*DNSProvenance, error) {
	if catalog == nil {
		return nil, errors.New("service bundle catalog is required")
	}
	if maxAnswers <= 0 {
		maxAnswers = MaxDNSAnswers
	}
	if maxAnswers > MaxDNSAnswers {
		return nil, fmt.Errorf("DNS provenance exceeds %d answers", MaxDNSAnswers)
	}
	return &DNSProvenance{catalog: catalog, maxAnswers: maxAnswers, answers: make(map[string]DNSAnswer)}, nil
}

func (p *DNSProvenance) Observe(observation DNSObservation, now time.Time) (DNSResolution, error) {
	if p == nil || p.catalog == nil {
		return DNSResolution{}, errors.New("DNS provenance is not initialized")
	}
	answer, err := p.normalizeObservation(observation, now.UTC())
	if err != nil {
		return DNSResolution{}, err
	}
	key := answerKey(answer)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purgeExpiredLocked(now.UTC())
	if _, exists := p.answers[key]; !exists && len(p.answers) >= p.maxAnswers {
		return DNSResolution{}, errors.New("DNS provenance capacity exceeded")
	}
	p.answers[key] = answer
	owners := p.ownersForAddressLocked(answer.Address)
	return resolutionFor(answer, owners), nil
}

func (p *DNSProvenance) Routable(bundleID, family string, now time.Time) []netip.Addr {
	if p == nil || (family != "ipv4" && family != "ipv6") {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purgeExpiredLocked(now.UTC())
	ownersByAddress := p.ownersByAddressLocked()
	addresses := make(map[string]netip.Addr)
	for _, answer := range p.answers {
		if answer.BundleID != bundleID || answer.Family != family {
			continue
		}
		owners := ownersByAddress[answer.Address]
		if len(owners) != 1 || owners[0] != bundleID {
			continue
		}
		address, err := netip.ParseAddr(answer.Address)
		if err == nil {
			addresses[address.String()] = address
		}
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	return result
}

func (p *DNSProvenance) Snapshot(now time.Time) []DNSResolution {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purgeExpiredLocked(now.UTC())
	ownersByAddress := p.ownersByAddressLocked()
	result := make([]DNSResolution, 0, len(p.answers))
	for _, answer := range p.answers {
		result = append(result, resolutionFor(answer, ownersByAddress[answer.Address]))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Answer.BundleID != result[j].Answer.BundleID {
			return result[i].Answer.BundleID < result[j].Answer.BundleID
		}
		if result[i].Answer.QueryName != result[j].Answer.QueryName {
			return result[i].Answer.QueryName < result[j].Answer.QueryName
		}
		return result[i].Answer.Address < result[j].Answer.Address
	})
	return result
}

func (p *DNSProvenance) Conflicts(now time.Time) []DNSConflict {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purgeExpiredLocked(now.UTC())
	ownersByAddress := p.ownersByAddressLocked()
	var conflicts []DNSConflict
	for address, owners := range ownersByAddress {
		if len(owners) > 1 {
			parsed, _ := netip.ParseAddr(address)
			family := "ipv6"
			if parsed.Is4() {
				family = "ipv4"
			}
			conflicts = append(conflicts, DNSConflict{Address: address, Family: family, Owners: owners})
		}
	}
	sort.Slice(conflicts, func(i, j int) bool { return conflicts[i].Address < conflicts[j].Address })
	return conflicts
}

func (p *DNSProvenance) normalizeObservation(observation DNSObservation, now time.Time) (DNSAnswer, error) {
	bundle, ok := p.catalog.Lookup(observation.BundleID)
	if !ok {
		return DNSAnswer{}, fmt.Errorf("unknown service bundle %q", observation.BundleID)
	}
	query, err := tspu.NormalizeDomain(observation.QueryName)
	if err != nil {
		return DNSAnswer{}, errors.New("invalid DNS query name")
	}
	owner, ok := p.catalog.LookupDomain(query)
	if !ok || owner.ID != bundle.ID {
		return DNSAnswer{}, fmt.Errorf("DNS query %s does not belong to bundle %s", query, bundle.ID)
	}
	chain, canonical, err := normalizeCNAMEChain(query, observation.CNAMEChain)
	if err != nil {
		return DNSAnswer{}, err
	}
	address, err := netip.ParseAddr(observation.Address)
	if err != nil || address.IsUnspecified() || address.IsMulticast() || address.Is4In6() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return DNSAnswer{}, errors.New("invalid DNS answer address")
	}
	if observation.TTLSeconds == 0 {
		return DNSAnswer{}, errors.New("DNS answer TTL must be positive")
	}
	if !digestPattern.MatchString(observation.CandidateHash) {
		return DNSAnswer{}, errors.New("DNS answer candidate hash is invalid")
	}
	if !revisionPattern.MatchString(observation.RevisionID) {
		return DNSAnswer{}, errors.New("DNS answer revision is invalid")
	}
	if !profileIDPattern.MatchString(observation.Source) {
		return DNSAnswer{}, errors.New("DNS answer source is invalid")
	}
	effective := time.Duration(observation.TTLSeconds) * time.Second
	if effective > MaxAnswerTTL {
		effective = MaxAnswerTTL
	}
	family := "ipv6"
	if address.Is4() {
		family = "ipv4"
	}
	if !containsValue(bundle.IPFamilies, family) {
		return DNSAnswer{}, fmt.Errorf("DNS answer family %s is outside bundle scope", family)
	}
	return DNSAnswer{
		BundleID: bundle.ID, QueryName: query, CanonicalName: canonical, CNAMEChain: chain,
		Address: address.String(), Family: family, OriginalTTLSeconds: observation.TTLSeconds,
		EffectiveTTLSeconds: uint32(effective / time.Second), ObservedAt: now, ExpiresAt: now.Add(effective),
		RevisionID: observation.RevisionID, CandidateHash: observation.CandidateHash, Source: observation.Source,
	}, nil
}

func normalizeCNAMEChain(query string, values []string) ([]string, string, error) {
	if len(values) > MaxCNAMEChain {
		return nil, "", fmt.Errorf("CNAME chain exceeds %d entries", MaxCNAMEChain)
	}
	seen := map[string]bool{query: true}
	chain := make([]string, 0, len(values))
	canonical := query
	for _, value := range values {
		domain, err := tspu.NormalizeDomain(value)
		if err != nil || seen[domain] {
			return nil, "", errors.New("invalid or cyclic CNAME chain")
		}
		seen[domain] = true
		chain = append(chain, domain)
		canonical = domain
	}
	return chain, canonical, nil
}

func (p *DNSProvenance) purgeExpiredLocked(now time.Time) {
	for key, answer := range p.answers {
		if !now.Before(answer.ExpiresAt) {
			delete(p.answers, key)
		}
	}
}

func (p *DNSProvenance) ownersForAddressLocked(address string) []string {
	seen := make(map[string]bool)
	for _, answer := range p.answers {
		if answer.Address == address {
			seen[answer.BundleID] = true
		}
	}
	owners := make([]string, 0, len(seen))
	for owner := range seen {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	return owners
}

func (p *DNSProvenance) ownersByAddressLocked() map[string][]string {
	sets := make(map[string]map[string]bool)
	for _, answer := range p.answers {
		if sets[answer.Address] == nil {
			sets[answer.Address] = make(map[string]bool)
		}
		sets[answer.Address][answer.BundleID] = true
	}
	result := make(map[string][]string, len(sets))
	for address, owners := range sets {
		values := make([]string, 0, len(owners))
		for owner := range owners {
			values = append(values, owner)
		}
		sort.Strings(values)
		result[address] = values
	}
	return result
}

func resolutionFor(answer DNSAnswer, owners []string) DNSResolution {
	answer.CNAMEChain = append([]string(nil), answer.CNAMEChain...)
	status := "OWNED"
	routable := len(owners) == 1 && owners[0] == answer.BundleID
	if !routable {
		status = "AMBIGUOUS"
	}
	return DNSResolution{Answer: answer, Status: status, Owners: append([]string(nil), owners...), Routable: routable}
}

func answerKey(answer DNSAnswer) string {
	return answer.BundleID + "\x00" + answer.QueryName + "\x00" + answer.Address
}

func containsValue(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
