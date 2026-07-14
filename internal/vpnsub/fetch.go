package vpnsub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

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
	SecretsShown bool   `json:"secrets_shown"`
}

func ReadSubscriptionURLFile(path string) (string, error) {
	raw, err := readSecretFile(path, 16<<10)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("subscription URL file must contain one URL")
	}
	parsed, err := validateSubscriptionURL(value)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
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
	if client == nil {
		client = &http.Client{}
	}
	requestClient := *client
	requestClient.Timeout = timeout
	redirects := 0
	requestClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		redirects = len(via)
		if len(via) > maxRedirects {
			return errors.New("subscription redirect limit exceeded")
		}
		if _, err := validateSubscriptionURL(req.URL.String()); err != nil {
			return err
		}
		return nil
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return FetchSummary{}, errors.New("subscription read failed")
	}
	if int64(len(raw)) == 0 || int64(len(raw)) > maxBytes {
		return FetchSummary{}, errors.New("subscription size limit exceeded")
	}
	if err := writeFileAtomic(outputPath, raw, 0o600); err != nil {
		return FetchSummary{}, err
	}
	return FetchSummary{
		Bytes: len(raw), SHA256: "sha256:" + sha256Hex(raw), Redirects: redirects, Output: outputPath, SecretsShown: false,
	}, nil
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
