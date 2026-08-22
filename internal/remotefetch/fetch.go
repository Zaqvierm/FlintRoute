// Package remotefetch provides the single outbound-fetch policy used by
// unprivileged controllers.  It validates every URL and pins each hostname to
// the addresses resolved before the request.  Callers must not bypass it for
// subscription, GeoIP or classification sources.
package remotefetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrHTTPSRequired     = errors.New("remote URL must use HTTPS")
	ErrPrivateTarget     = errors.New("remote URL resolves to a private or special address")
	ErrUnsafeRedirect    = errors.New("remote redirect target is unsafe")
	ErrRedirectLimit     = errors.New("remote redirect limit exceeded")
	ErrInvalidRemoteURL  = errors.New("remote URL is invalid")
	ErrResolutionFailure = errors.New("remote URL could not be resolved")
	ErrResponseTooLarge  = errors.New("remote response exceeds size limit")
)

type testLoopbackKey struct{}

// WithLoopbackForTests enables loopback targets for in-process TLS test
// servers. It is intentionally not reachable by production callers.
func WithLoopbackForTests(ctx context.Context) context.Context {
	return context.WithValue(ctx, testLoopbackKey{}, true)
}

// ReadBounded consumes at most maxBytes from a response body.  It is applied
// after net/http decompression, so a compressed response cannot bypass the
// caller's memory budget with a decompression bomb.
func ReadBounded(body io.Reader, maxBytes int64) ([]byte, error) {
	if body == nil || maxBytes <= 0 {
		return nil, ErrResponseTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

// CopyBounded is the streaming counterpart for large immutable artifacts.
// The count is returned even when the limit is exceeded so callers can emit
// bounded diagnostics without retaining the response in memory.
func CopyBounded(dst io.Writer, body io.Reader, maxBytes int64) (int64, error) {
	if dst == nil || body == nil || maxBytes <= 0 {
		return 0, ErrResponseTooLarge
	}
	written, err := io.Copy(dst, io.LimitReader(body, maxBytes+1))
	if err != nil {
		return written, err
	}
	if written > maxBytes {
		return written, ErrResponseTooLarge
	}
	return written, nil
}

type Options struct {
	MaxRedirects int
	Timeout      time.Duration
	Redirects    *int
}

type pinnedTransport struct {
	base  *http.Transport
	ctx   context.Context
	mu    sync.RWMutex
	pins  map[string][]netip.Addr
	allow bool
}

func NewClient(ctx context.Context, base *http.Client, rawURL string, opts Options) (*http.Client, error) {
	parsed, err := validateURL(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	if opts.MaxRedirects <= 0 || opts.MaxRedirects > 5 {
		opts.MaxRedirects = 3
	}
	if opts.Timeout <= 0 || opts.Timeout > 2*time.Minute {
		opts.Timeout = 30 * time.Second
	}
	transport := cloneTransport(base)
	pinned := &pinnedTransport{
		base:  transport.Clone(),
		ctx:   ctx,
		pins:  make(map[string][]netip.Addr),
		allow: ctx.Value(testLoopbackKey{}) == true,
	}
	if err := pinned.pin(parsed); err != nil {
		return nil, err
	}
	transport.DialContext = pinned.dialContext
	client := &http.Client{Transport: transport, Timeout: opts.Timeout}
	if base != nil {
		client.CheckRedirect = base.CheckRedirect
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= opts.MaxRedirects {
			return ErrRedirectLimit
		}
		if _, err := validateURL(ctx, req.URL.String()); err != nil {
			return fmt.Errorf("%w: %v", ErrUnsafeRedirect, err)
		}
		if err := pinned.pin(req.URL); err != nil {
			return fmt.Errorf("%w: %v", ErrUnsafeRedirect, err)
		}
		if opts.Redirects != nil {
			*opts.Redirects = len(via) + 1
		}
		return nil
	}
	return client, nil
}

func cloneTransport(base *http.Client) *http.Transport {
	if base != nil {
		if transport, ok := base.Transport.(*http.Transport); ok {
			return transport.Clone()
		}
	}
	return http.DefaultTransport.(*http.Transport).Clone()
}

func validateURL(ctx context.Context, raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, ErrHTTPSRequired
	}
	if strings.TrimSpace(parsed.Hostname()) == "" {
		return nil, ErrInvalidRemoteURL
	}
	if err := validateHost(ctx, parsed.Hostname()); err != nil {
		return nil, err
	}
	return parsed, nil
}

func validateHost(ctx context.Context, host string) error {
	allowLoopback := ctx.Value(testLoopbackKey{}) == true
	if parsed, err := netip.ParseAddr(host); err == nil {
		if forbidden(parsed, allowLoopback) {
			return ErrPrivateTarget
		}
		return nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return ErrResolutionFailure
	}
	for _, address := range addresses {
		if forbidden(address, allowLoopback) {
			return ErrPrivateTarget
		}
	}
	return nil
}

func forbidden(address netip.Addr, allowLoopback bool) bool {
	if !address.IsValid() {
		return true
	}
	if address.IsLoopback() && allowLoopback {
		return false
	}
	if address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return true
	}
	if address.IsPrivate() {
		return true
	}
	// RFC 6598 shared address space (100.64.0.0/10) is not covered by
	// netip.Addr.IsPrivate, but is not a safe remote fetch target either.
	if address.Is4() {
		value := address.As4()
		if value[0] == 100 && value[1]&0xc0 == 64 {
			return true
		}
	}
	return false
}

func (p *pinnedTransport) pin(parsed *url.URL) error {
	host := strings.ToLower(parsed.Hostname())
	addresses := make([]netip.Addr, 0, 2)
	if address, err := netip.ParseAddr(host); err == nil {
		if forbidden(address, p.allow) {
			return ErrPrivateTarget
		}
		addresses = append(addresses, address)
	} else {
		lookupCtx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
		resolved, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", host)
		cancel()
		if err != nil || len(resolved) == 0 {
			return ErrResolutionFailure
		}
		for _, address := range resolved {
			if forbidden(address, p.allow) {
				return ErrPrivateTarget
			}
			addresses = append(addresses, address)
		}
	}
	p.mu.Lock()
	p.pins[host] = addresses
	p.mu.Unlock()
	return nil
}

func (p *pinnedTransport) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	hostKey := strings.ToLower(strings.Trim(host, "[]"))
	p.mu.RLock()
	addresses := append([]netip.Addr(nil), p.pins[hostKey]...)
	p.mu.RUnlock()
	if len(addresses) == 0 {
		return nil, ErrResolutionFailure
	}
	var last error
	for _, resolved := range addresses {
		connection, dialErr := p.base.DialContext(ctx, network, net.JoinHostPort(resolved.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		last = dialErr
	}
	return nil, last
}

// ValidatePort is shared by callers that need to validate a URL port without
// constructing a client. It intentionally rejects malformed numeric ports.
func ValidatePort(raw string) error {
	if raw == "" {
		return nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return ErrInvalidRemoteURL
	}
	return nil
}
