package tspu

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"router-policy/internal/config"
)

const (
	CacheVersion  = 2
	maxCacheBytes = 32 << 20
)

type Cache struct {
	Version        int              `json:"version"`
	SHA256         string           `json:"sha256"`
	PreviousSHA256 string           `json:"previous_sha256,omitempty"`
	GeneratedAt    time.Time        `json:"generated_at"`
	ExpiresAt      time.Time        `json:"expires_at"`
	FreshSources   int              `json:"fresh_sources"`
	Sources        []SourceReport   `json:"sources"`
	Entries        map[string]Entry `json:"entries"`
}

type Entry struct {
	Domain     string    `json:"domain"`
	MatchType  string    `json:"match_type"`
	Source     string    `json:"source"`
	Provenance []string  `json:"provenance"`
	Confidence float64   `json:"confidence"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type SourceReport struct {
	Name             string    `json:"name"`
	Type             string    `json:"type"`
	URL              string    `json:"url"`
	FinalURL         string    `json:"final_url,omitempty"`
	Entries          int       `json:"entries"`
	PreviousEntries  int       `json:"previous_entries,omitempty"`
	Bytes            int       `json:"bytes,omitempty"`
	SHA256           string    `json:"sha256,omitempty"`
	ETag             string    `json:"etag,omitempty"`
	LastModified     string    `json:"last_modified,omitempty"`
	Accepted         bool      `json:"accepted"`
	Fresh            bool      `json:"fresh"`
	NotModified      bool      `json:"not_modified"`
	RetainedPrevious bool      `json:"retained_previous"`
	Redirects        int       `json:"redirects"`
	DropRatio        float64   `json:"drop_ratio,omitempty"`
	Confidence       float64   `json:"confidence"`
	RetrievedAt      time.Time `json:"retrieved_at,omitempty"`
	Reason           string    `json:"reason,omitempty"`
}

type Match struct {
	Domain     string   `json:"domain"`
	Matched    string   `json:"matched"`
	MatchType  string   `json:"match_type"`
	Source     string   `json:"source"`
	Provenance []string `json:"provenance"`
	Confidence float64  `json:"confidence"`
	Expired    bool     `json:"expired"`
	Status     string   `json:"status"`
	Evidence   string   `json:"evidence"`
}

type fetchedSource struct {
	Domains      []string
	Bytes        int
	SHA256       string
	ETag         string
	LastModified string
	FinalURL     string
	Redirects    int
	NotModified  bool
}

func Load(path string) (Cache, error) {
	raw, err := readBoundedRegular(path, maxCacheBytes)
	if err != nil {
		return Cache{}, err
	}
	cache, err := decodeCache(raw)
	if err != nil {
		return Cache{}, err
	}
	return cache, nil
}

func Save(path string, cache Cache) error {
	cache = finalizeCache(cache)
	raw, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if current, err := readBoundedRegular(path, maxCacheBytes); err == nil {
		if _, decodeErr := decodeCache(current); decodeErr != nil {
			return fmt.Errorf("existing TSPU cache is invalid: %w", decodeErr)
		}
		if err := writeAtomic(previousPath(path), current, 0o600); err != nil {
			return fmt.Errorf("write previous TSPU cache: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeAtomic(path, raw, 0o600)
}

func PreviousPath(path string) string { return previousPath(path) }

func ParseDomains(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	seen := map[string]bool{}
	var out []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = strings.TrimSpace(line[:comment])
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		candidate := fields[0]
		if net.ParseIP(candidate) != nil && len(fields) > 1 {
			candidate = fields[1]
		}
		candidate = strings.TrimPrefix(candidate, "||")
		candidate = strings.TrimSuffix(candidate, "^")
		candidate = strings.TrimPrefix(candidate, ".")
		if strings.ContainsAny(candidate, "/:@?") {
			continue
		}
		pattern, _, err := normalizePattern(candidate)
		if err != nil {
			continue
		}
		if !seen[pattern] {
			seen[pattern] = true
			out = append(out, pattern)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func NormalizeDomain(domain string) (string, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" || strings.Contains(domain, "*") {
		return "", errors.New("invalid domain")
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", errors.New("invalid IDN domain")
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if ascii == "" || len(ascii) > 253 || net.ParseIP(ascii) != nil {
		return "", errors.New("invalid domain")
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", errors.New("domain must contain a public suffix")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid domain label")
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return "", errors.New("invalid domain label character")
			}
		}
	}
	return ascii, nil
}

func ETLDPlusOne(domain string) string {
	domain, err := NormalizeDomain(domain)
	if err != nil {
		return ""
	}
	base, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return base
}

func BuildCache(now time.Time, ttl time.Duration, reports []SourceReport, bySource map[string][]string) Cache {
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	now = now.UTC()
	cache := Cache{Version: CacheVersion, GeneratedAt: now, ExpiresAt: now.Add(ttl), Sources: reports, Entries: map[string]Entry{}}
	for _, report := range reports {
		if !report.Accepted && !report.RetainedPrevious {
			continue
		}
		if report.Fresh {
			cache.FreshSources++
		}
		for _, pattern := range bySource[report.Name] {
			domain, matchType, err := normalizePattern(pattern)
			if err != nil {
				continue
			}
			entry := cache.Entries[domain]
			if entry.Domain == "" {
				entry = Entry{Domain: domain, MatchType: matchType, Confidence: report.Confidence, FirstSeen: now, LastSeen: now, ExpiresAt: cache.ExpiresAt}
			}
			entry.Provenance = appendUnique(entry.Provenance, report.Name)
			sort.Strings(entry.Provenance)
			entry.Source = entry.Provenance[0]
			if report.Confidence > entry.Confidence {
				entry.Confidence = report.Confidence
			}
			cache.Entries[domain] = entry
		}
	}
	return finalizeCache(cache)
}

func Find(cache Cache, domain string, now time.Time) (Match, bool) {
	domain, err := NormalizeDomain(domain)
	if err != nil {
		return Match{}, false
	}
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		if entry, ok := cache.Entries[candidate]; ok && entry.MatchType != "wildcard" {
			return matchForEntry(cache, domain, candidate, entry, now), true
		}
		if i > 0 {
			wildcard := "*." + candidate
			if entry, ok := cache.Entries[wildcard]; ok && entry.MatchType == "wildcard" {
				return matchForEntry(cache, domain, wildcard, entry, now), true
			}
		}
	}
	return Match{}, false
}

func Update(ctx context.Context, client *http.Client, sources []config.TSPUSource, maxBytes int64, ttl time.Duration, now time.Time) (Cache, error) {
	return UpdateWithPrevious(ctx, client, sources, maxBytes, ttl, now, nil)
}

func UpdateWithPrevious(ctx context.Context, client *http.Client, sources []config.TSPUSource, maxBytes int64, ttl time.Duration, now time.Time, previous *Cache) (Cache, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if maxBytes <= 0 {
		maxBytes = 10 << 20
	}
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	now = now.UTC()
	previousReports := map[string]SourceReport{}
	if previous != nil {
		for _, report := range previous.Sources {
			previousReports[report.Name] = report
		}
	}
	seenSources := map[string]bool{}
	var reports []SourceReport
	bySource := map[string][]string{}
	freshSources := map[string]bool{}
	for _, source := range sources {
		report := SourceReport{Name: source.Name, Type: source.Type, URL: source.URL, Confidence: 0.9}
		oldReport := previousReports[source.Name]
		oldDomains := domainsForSource(previous, source.Name)
		report.PreviousEntries = len(oldDomains)
		if seenSources[source.Name] || !validSourceName(source.Name) || source.Type != "domains" {
			report.Reason = "invalid_or_duplicate_source"
			reports = append(reports, retainPrevious(report, oldDomains, bySource))
			continue
		}
		seenSources[source.Name] = true
		fetched, err := fetchSource(ctx, client, source.URL, maxBytes, oldReport, 3)
		if err != nil {
			report.Reason = err.Error()
			reports = append(reports, retainPrevious(report, oldDomains, bySource))
			continue
		}
		report.FinalURL = fetched.FinalURL
		report.Bytes = fetched.Bytes
		report.SHA256 = fetched.SHA256
		report.ETag = fetched.ETag
		report.LastModified = fetched.LastModified
		report.Redirects = fetched.Redirects
		report.NotModified = fetched.NotModified
		report.RetrievedAt = now
		domains := fetched.Domains
		if fetched.NotModified {
			domains = oldDomains
			report.SHA256 = oldReport.SHA256
			report.ETag = firstNonEmpty(fetched.ETag, oldReport.ETag)
			report.LastModified = firstNonEmpty(fetched.LastModified, oldReport.LastModified)
		}
		report.Entries = len(domains)
		if len(domains) < source.MinEntries {
			report.Reason = fmt.Sprintf("too_few_entries:%d", len(domains))
			reports = append(reports, retainPrevious(report, oldDomains, bySource))
			continue
		}
		if len(oldDomains) > 0 && len(domains) < len(oldDomains) {
			report.DropRatio = float64(len(oldDomains)-len(domains)) / float64(len(oldDomains))
			if source.MaxDropRatio >= 0 && source.MaxDropRatio < 1 && report.DropRatio > source.MaxDropRatio {
				report.Reason = fmt.Sprintf("drop_ratio_exceeded:%.6f", report.DropRatio)
				reports = append(reports, retainPrevious(report, oldDomains, bySource))
				continue
			}
		}
		report.Accepted = true
		report.Fresh = true
		bySource[source.Name] = domains
		freshSources[source.Name] = true
		reports = append(reports, report)
	}
	cache := BuildCache(now, ttl, reports, bySource)
	if previous != nil {
		cache.PreviousSHA256 = previous.SHA256
		for pattern, entry := range cache.Entries {
			old, exists := previous.Entries[pattern]
			if !exists {
				continue
			}
			entry.FirstSeen = old.FirstSeen
			fresh := false
			for _, source := range entry.Provenance {
				fresh = fresh || freshSources[source]
			}
			if !fresh {
				entry.LastSeen = old.LastSeen
				entry.ExpiresAt = old.ExpiresAt
			}
			cache.Entries[pattern] = entry
		}
		cache = finalizeCache(cache)
	}
	if cache.FreshSources == 0 {
		return cache, errors.New("no fresh accepted TSPU source entries; previous cache retained")
	}
	if len(cache.Entries) == 0 {
		return cache, errors.New("no accepted TSPU source entries")
	}
	return cache, nil
}

func fetchSource(ctx context.Context, client *http.Client, rawURL string, maxBytes int64, previous SourceReport, maxRedirects int) (fetchedSource, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fetchedSource{}, errors.New("source_url_must_be_https")
	}
	copyClient := *client
	redirects := 0
	copyClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		redirects = len(via)
		if redirects > maxRedirects || request.URL.Scheme != "https" || request.URL.Host == "" || request.URL.User != nil || request.URL.Fragment != "" {
			return errors.New("unsafe_source_redirect")
		}
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return fetchedSource{}, err
	}
	request.Header.Set("User-Agent", "router-policy-tspu-updater/0.2")
	if previous.ETag != "" {
		request.Header.Set("If-None-Match", previous.ETag)
	}
	if previous.LastModified != "" {
		request.Header.Set("If-Modified-Since", previous.LastModified)
	}
	response, err := copyClient.Do(request)
	if err != nil {
		return fetchedSource{}, err
	}
	defer response.Body.Close()
	result := fetchedSource{
		ETag: response.Header.Get("ETag"), LastModified: response.Header.Get("Last-Modified"),
		FinalURL: response.Request.URL.String(), Redirects: redirects,
	}
	if response.StatusCode == http.StatusNotModified {
		if previous.Entries == 0 {
			return fetchedSource{}, errors.New("not_modified_without_previous_entries")
		}
		result.NotModified = true
		return result, nil
	}
	if response.StatusCode != http.StatusOK {
		return fetchedSource{}, fmt.Errorf("http_%d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return fetchedSource{}, err
	}
	if int64(len(raw)) > maxBytes {
		return fetchedSource{}, errors.New("source_size_limit_exceeded")
	}
	result.Bytes = len(raw)
	result.SHA256 = hashBytes(raw)
	result.Domains, err = ParseDomains(bytes.NewReader(raw))
	if err != nil {
		return fetchedSource{}, err
	}
	return result, nil
}

func normalizePattern(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	matchType := "suffix"
	if strings.HasPrefix(value, "*.") {
		matchType = "wildcard"
		value = strings.TrimPrefix(value, "*.")
	}
	if strings.Contains(value, "*") {
		return "", "", errors.New("wildcard is only allowed as the leftmost label")
	}
	domain, err := NormalizeDomain(value)
	if err != nil {
		return "", "", err
	}
	if matchType == "wildcard" {
		return "*." + domain, matchType, nil
	}
	return domain, matchType, nil
}

func matchForEntry(cache Cache, domain, matched string, entry Entry, now time.Time) Match {
	expires := entry.ExpiresAt
	if expires.IsZero() {
		expires = cache.ExpiresAt
	}
	expired := !expires.IsZero() && !now.UTC().Before(expires)
	status := "MATCH"
	evidence := "tspu_cache_match"
	if expired {
		status = "STALE_MATCH"
		evidence = "tspu_cache_stale_match"
	}
	return Match{
		Domain: domain, Matched: matched, MatchType: entry.MatchType, Source: entry.Source,
		Provenance: append([]string(nil), entry.Provenance...), Confidence: entry.Confidence,
		Expired: expired, Status: status, Evidence: evidence,
	}
}

func retainPrevious(report SourceReport, domains []string, bySource map[string][]string) SourceReport {
	if len(domains) == 0 {
		return report
	}
	report.RetainedPrevious = true
	report.Fresh = false
	bySource[report.Name] = domains
	return report
}

func domainsForSource(previous *Cache, source string) []string {
	if previous == nil || source == "" {
		return nil
	}
	var domains []string
	for pattern, entry := range previous.Entries {
		if contains(entry.Provenance, source) || entry.Source == source {
			domains = append(domains, pattern)
		}
	}
	sort.Strings(domains)
	return domains
}

func finalizeCache(cache Cache) Cache {
	cache.Version = CacheVersion
	if cache.Entries == nil {
		cache.Entries = map[string]Entry{}
	}
	for pattern, entry := range cache.Entries {
		entry.Provenance = uniqueStrings(entry.Provenance)
		sort.Strings(entry.Provenance)
		if entry.Source == "" && len(entry.Provenance) > 0 {
			entry.Source = entry.Provenance[0]
		}
		cache.Entries[pattern] = entry
	}
	cache.SHA256 = ""
	raw, _ := json.Marshal(cache)
	cache.SHA256 = hashBytes(raw)
	return cache
}

func decodeCache(raw []byte) (Cache, error) {
	var cache Cache
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&cache); err != nil {
		return Cache{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Cache{}, errors.New("trailing data in TSPU cache")
	}
	if cache.Entries == nil || cache.GeneratedAt.IsZero() || cache.ExpiresAt.IsZero() {
		return Cache{}, errors.New("incomplete TSPU cache")
	}
	if cache.Version < CacheVersion {
		for pattern, entry := range cache.Entries {
			normalized, matchType, err := normalizePattern(pattern)
			if err != nil || normalized != pattern {
				return Cache{}, fmt.Errorf("invalid legacy TSPU cache entry: %s", pattern)
			}
			entry.Domain = pattern
			entry.MatchType = matchType
			if len(entry.Provenance) == 0 && entry.Source != "" {
				entry.Provenance = []string{entry.Source}
			}
			if entry.ExpiresAt.IsZero() {
				entry.ExpiresAt = cache.ExpiresAt
			}
			cache.Entries[pattern] = entry
		}
		cache = finalizeCache(cache)
	}
	if cache.Version >= CacheVersion {
		expected := cache.SHA256
		if expected == "" || finalizeCache(cache).SHA256 != expected {
			return Cache{}, errors.New("TSPU cache hash mismatch")
		}
	}
	for pattern, entry := range cache.Entries {
		normalized, matchType, err := normalizePattern(pattern)
		if err != nil || normalized != pattern || entry.Domain != pattern || entry.MatchType != matchType {
			return Cache{}, fmt.Errorf("invalid TSPU cache entry: %s", pattern)
		}
	}
	return cache, nil
}

func writeAtomic(path string, raw []byte, mode os.FileMode) error {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := path + ".tmp." + hex.EncodeToString(random)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := replaceFile(temporary, path); err != nil {
		return err
	}
	remove = false
	return nil
}

func replaceFile(source, target string) error {
	if err := os.Rename(source, target); err == nil {
		return nil
	}
	backup := target + ".replace-backup"
	_ = os.Remove(backup)
	if err := os.Rename(target, backup); err != nil {
		return err
	}
	if err := os.Rename(source, target); err != nil {
		_ = os.Rename(backup, target)
		return err
	}
	_ = os.Remove(backup)
	return nil
}

func readBoundedRegular(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBytes {
		return nil, errors.New("invalid TSPU cache file")
	}
	return os.ReadFile(path)
}

func previousPath(path string) string {
	extension := filepath.Ext(path)
	return strings.TrimSuffix(path, extension) + ".previous" + extension
}

func validSourceName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func hashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func appendUnique(values []string, value string) []string {
	if contains(values, value) {
		return values
	}
	return append(values, value)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
