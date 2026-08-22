package vpnsub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"router-policy/internal/remotefetch"
)

const maxSubscriptionSources = 5

type FetchOptions struct {
	MaxBytes     int64
	MaxRedirects int
	Timeout      time.Duration
}

type FetchSummary struct {
	Bytes        int    `json:"bytes"`
	SHA256       string `json:"sha256"`
	Redirects    int    `json:"redirects"`
	Output       string `json:"output"`
	ProviderName string `json:"provider_name,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	SecretsShown bool   `json:"secrets_shown"`
}

func ReadSubscriptionURLFile(path string) (string, error) {
	values, err := ReadSubscriptionURLFiles(path)
	if err != nil {
		return "", err
	}
	if len(values) != 1 {
		return "", errors.New("subscription URL file contains multiple sources")
	}
	return values[0], nil
}

func ReadSubscriptionURLFiles(path string) ([]string, error) {
	raw, err := readSecretFile(path, 16<<10)
	if err != nil {
		return nil, err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" || strings.ContainsRune(value, '\x00') {
		return nil, errors.New("subscription URL file is empty or invalid")
	}
	values := []string{value}
	if strings.HasPrefix(value, "[") {
		if err := json.Unmarshal(raw, &values); err != nil {
			return nil, errors.New("subscription URL file contains invalid JSON")
		}
	}
	if len(values) == 0 || len(values) > maxSubscriptionSources {
		return nil, fmt.Errorf("subscription URL file must contain 1..%d sources", maxSubscriptionSources)
	}
	normalized := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, candidate := range values {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || strings.ContainsAny(candidate, "\r\n\x00") {
			return nil, errors.New("subscription URL must be one line")
		}
		parsed, err := validateSubscriptionURL(candidate)
		if err != nil {
			return nil, err
		}
		canonical := parsed.String()
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		normalized = append(normalized, canonical)
	}
	if len(normalized) == 0 {
		return nil, errors.New("subscription URL file contains no unique sources")
	}
	return normalized, nil
}

func FetchSubscription(ctx context.Context, client *http.Client, subscriptionURL, outputPath string, opts FetchOptions) (FetchSummary, error) {
	parsed, err := validateSubscriptionURL(subscriptionURL)
	if err != nil {
		return FetchSummary{}, err
	}
	if outputPath == "" {
		return FetchSummary{}, errors.New("subscription output path is required")
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 || maxBytes > maxSubscriptionFileBytes {
		maxBytes = maxSubscriptionFileBytes
	}
	maxRedirects := opts.MaxRedirects
	if maxRedirects <= 0 || maxRedirects > 5 {
		maxRedirects = 3
	}
	timeout := opts.Timeout
	if timeout <= 0 || timeout > time.Minute {
		timeout = 30 * time.Second
	}
	redirects := 0
	requestClient, err := remotefetch.NewClient(ctx, client, parsed.String(), remotefetch.Options{
		MaxRedirects: maxRedirects,
		Timeout:      timeout,
		Redirects:    &redirects,
	})
	if err != nil {
		return FetchSummary{}, errors.New("subscription endpoint is not allowed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return FetchSummary{}, errors.New("subscription request creation failed")
	}
	req.Header.Set("User-Agent", "router-policy-subscription/1")
	resp, err := requestClient.Do(req)
	if err != nil {
		return FetchSummary{}, errors.New("subscription download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return FetchSummary{}, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return FetchSummary{}, errors.New("subscription size limit exceeded")
	}
	raw, err := remotefetch.ReadBounded(resp.Body, maxBytes)
	if err != nil {
		if errors.Is(err, remotefetch.ErrResponseTooLarge) {
			return FetchSummary{}, errors.New("subscription size limit exceeded")
		}
		return FetchSummary{}, errors.New("subscription read failed")
	}
	if len(raw) == 0 {
		return FetchSummary{}, errors.New("subscription size limit exceeded")
	}
	if err := writeFileAtomic(outputPath, raw, 0o600); err != nil {
		return FetchSummary{}, err
	}
	return FetchSummary{
		Bytes: len(raw), SHA256: "sha256:" + sha256Hex(raw), Redirects: redirects, Output: outputPath,
		ProviderName: safeProviderName(resp.Header.Get("profile-title")), ExpiresAt: subscriptionExpiry(resp.Header.Get("subscription-userinfo")),
		SecretsShown: false,
	}, nil
}

func safeProviderName(value string) string {
	value = strings.TrimSpace(value)
	if decoded, err := url.QueryUnescape(value); err == nil {
		value = decoded
	}
	if value == "" || len(value) > 96 || strings.ContainsAny(value, "\r\n\x00") {
		return ""
	}
	return value
}

func subscriptionExpiry(value string) string {
	for _, field := range strings.Split(value, ";") {
		parts := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "expire" {
			continue
		}
		seconds, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil || seconds <= 0 {
			return ""
		}
		return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
	}
	return ""
}

func validateSubscriptionURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("subscription URL must be HTTPS without userinfo")
	}
	if parsed.Fragment != "" {
		return nil, errors.New("subscription URL fragment is forbidden")
	}
	return parsed, nil
}

func readSecretFile(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxBytes {
		return nil, errors.New("secret file is unsafe or oversized")
	}
	if runtimeModeMustBe0600() && info.Mode().Perm() != 0o600 {
		return nil, errors.New("secret file must have mode 0600")
	}
	return os.ReadFile(path)
}

func runtimeModeMustBe0600() bool {
	return os.PathSeparator != '\\'
}
