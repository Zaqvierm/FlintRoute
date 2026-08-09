package vpnsub

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
	"time"

	"golang.org/x/net/proxy"
)

const cloudflareDownloadEndpoint = "https://speed.cloudflare.com/__down"

type SpeedMeasurement struct {
	MeasuredMbps float64 `json:"measured_mbps"`
	BytesUsed    int64   `json:"bytes_used"`
	DurationMS   int64   `json:"duration_ms"`
	TestedAt     string  `json:"tested_at"`
}

type ThroughputTester interface {
	Measure(context.Context, string, int64) (SpeedMeasurement, error)
}

type CloudflareThroughputTester struct {
	Endpoint string
	Timeout  time.Duration
}

func NewCloudflareThroughputTester() CloudflareThroughputTester {
	return CloudflareThroughputTester{Endpoint: cloudflareDownloadEndpoint, Timeout: 20 * time.Second}
}

func (t CloudflareThroughputTester) Measure(ctx context.Context, socksAddress string, bytesToRead int64) (SpeedMeasurement, error) {
	if bytesToRead < 1<<20 || bytesToRead > 16<<20 {
		return SpeedMeasurement{}, errors.New("speed test size must be between 1 and 16 MiB")
	}
	host, _, err := net.SplitHostPort(socksAddress)
	if err != nil {
		return SpeedMeasurement{}, errors.New("candidate SOCKS endpoint is invalid")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() {
		return SpeedMeasurement{}, errors.New("speed test requires a loopback candidate SOCKS endpoint")
	}
	endpoint := t.Endpoint
	if endpoint == "" {
		endpoint = cloudflareDownloadEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "speed.cloudflare.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return SpeedMeasurement{}, errors.New("speed test endpoint is not allowlisted")
	}
	values := parsed.Query()
	values.Set("bytes", strconv.FormatInt(bytesToRead, 10))
	parsed.RawQuery = values.Encode()
	timeout := t.Timeout
	if timeout <= 0 || timeout > time.Minute {
		timeout = 20 * time.Second
	}
	baseDialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}
	socksDialer, err := proxy.SOCKS5("tcp", socksAddress, nil, baseDialer)
	if err != nil {
		return SpeedMeasurement{}, errors.New("candidate SOCKS setup failed")
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			if contextDialer, ok := socksDialer.(proxy.ContextDialer); ok {
				return contextDialer.DialContext(dialCtx, network, address)
			}
			return socksDialer.Dial(network, address)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return SpeedMeasurement{}, errors.New("speed test request could not be created")
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "FlintRoute speed measurement")
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return SpeedMeasurement{}, errors.New("VLESS speed test request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return SpeedMeasurement{}, fmt.Errorf("VLESS speed test returned HTTP %d", response.StatusCode)
	}
	read, err := io.Copy(io.Discard, io.LimitReader(response.Body, bytesToRead+1))
	if err != nil {
		return SpeedMeasurement{}, errors.New("VLESS speed test download failed")
	}
	if read != bytesToRead {
		return SpeedMeasurement{}, errors.New("VLESS speed test returned an unexpected payload size")
	}
	elapsed := time.Since(started)
	if elapsed <= 0 {
		return SpeedMeasurement{}, errors.New("VLESS speed test duration is invalid")
	}
	return SpeedMeasurement{
		MeasuredMbps: float64(read*8) / elapsed.Seconds() / 1_000_000,
		BytesUsed:    read, DurationMS: elapsed.Milliseconds(), TestedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func SpeedTestBytes(tariffMbps float64) int64 {
	if tariffMbps <= 0 {
		tariffMbps = 300
	}
	bytes := int64(tariffMbps * 1_000_000 / 8 * 0.35)
	if bytes < 2<<20 {
		return 2 << 20
	}
	if bytes > 16<<20 {
		return 16 << 20
	}
	return bytes
}
