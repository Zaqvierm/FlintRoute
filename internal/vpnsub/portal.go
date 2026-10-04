package vpnsub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"router-policy/internal/remotefetch"
)

// A connect link is an enrollment document, not a subscription. Recognition
// is deliberately provider-specific; arbitrary HTML pages are never scraped.
func portalEnrollmentEndpoint(raw string) (string, bool, error) {
	value, err := NormalizeSource(raw)
	if err != nil {
		return "", false, err
	}
	u, err := url.Parse(value)
	if err != nil || !strings.EqualFold(u.Hostname(), "portal.noclip.ink") {
		return "", false, nil
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	var token string
	switch {
	case len(parts) == 2 && parts[0] == "connect":
		token = parts[1]
	case len(parts) == 4 && parts[0] == "api" && parts[1] == "device-enrollment" && parts[3] == "happ":
		token = parts[2]
	default:
		if strings.HasPrefix(u.Path, "/connect/") || strings.HasPrefix(u.Path, "/api/device-enrollment/") {
			return "", true, &SourceError{Code: "portal_source_invalid", Message: "portal enrollment path is malformed"}
		}
		return "", false, nil
	}
	if !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.Port() != "" || u.Fragment != "" || len(token) == 0 || len(token) > 256 {
		return "", true, &SourceError{Code: "portal_source_invalid", Message: "portal enrollment source is invalid"}
	}
	for _, c := range token {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return "", true, &SourceError{Code: "portal_source_invalid", Message: "portal enrollment token is malformed"}
		}
	}
	u.Path = "/api/device-enrollment/" + token + "/happ"
	u.Scheme = "https"
	u.RawPath = ""
	return u.String(), true, nil
}

func fetchPortalHappSource(ctx context.Context, base *http.Client, endpoint string) (string, error) {
	client, err := remotefetch.NewClient(ctx, base, endpoint, remotefetch.Options{Timeout: 20 * time.Second, MaxRedirects: 1})
	if err != nil {
		return "", &SourceError{Code: "portal_endpoint_not_allowed", Message: "portal endpoint is not allowed"}
	}
	defer client.CloseIdleConnections()
	// Enrollment tokens must not be forwarded to another origin or endpoint.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", &SourceError{Code: "portal_request_failed", Message: "portal request creation failed"}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Happ/3.26.1")
	resp, err := client.Do(req)
	if err != nil {
		return "", &SourceError{Code: "portal_request_failed", Message: "portal enrollment request failed"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &SourceError{Code: "portal_http_failure", Message: "portal enrollment returned an unsuccessful HTTP status"}
	}
	body, err := remotefetch.ReadBounded(resp.Body, 64<<10)
	if err != nil {
		return "", &SourceError{Code: "portal_response_invalid", Message: "portal enrollment response exceeded its limit or could not be read"}
	}
	var document struct {
		HappImportURL string `json:"happImportUrl"`
	}
	if json.Unmarshal(body, &document) != nil {
		return "", &SourceError{Code: "portal_response_invalid", Message: "portal enrollment did not return a valid JSON document"}
	}
	info, err := DetectSource(document.HappImportURL)
	if err != nil || info.Type != SourceTypeHapp || info.WrappedSource != "" {
		return "", &SourceError{Code: "portal_response_invalid", Message: "portal enrollment did not return a Happ source"}
	}
	return info.Canonical, nil
}

func resolveFetchSource(ctx context.Context, client *http.Client, original string, resolver SourceResolving) (SourceResolution, error) {
	endpoint, present, err := portalEnrollmentEndpoint(original)
	if err != nil {
		return SourceResolution{}, err
	}
	if !present {
		return resolver.Resolve(ctx, original)
	}
	happ, err := fetchPortalHappSource(ctx, client, endpoint)
	if err != nil {
		return SourceResolution{}, err
	}
	resolved, err := resolver.Resolve(ctx, happ)
	if err != nil {
		return SourceResolution{}, err
	}
	// Keep the enrollment link as the canonical source for refresh. Neither
	// the token nor the intermediate crypt payload enters API diagnostics.
	resolved.OriginalSource, _ = NormalizeSource(original)
	resolved.OriginalSourceMasked = "https://portal.noclip.ink/connect/****"
	return resolved, nil
}
