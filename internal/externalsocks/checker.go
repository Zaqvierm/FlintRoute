package externalsocks

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type CheckRequest struct {
	Endpoint   string `json:"endpoint"`
	TestDomain string `json:"test_domain"`
}

type CheckReport struct {
	Ready           bool   `json:"ready"`
	Endpoint        string `json:"endpoint"`
	Dependency      string `json:"dependency"`
	ManagedBy       string `json:"managed_by"`
	TCPReachable    bool   `json:"tcp_reachable"`
	SOCKS5Handshake bool   `json:"socks5_handshake"`
	RemoteConnect   bool   `json:"remote_connect"`
	TLSVerified     bool   `json:"tls_verified"`
	HTTPStatus      int    `json:"http_status"`
	TestDomain      string `json:"test_domain"`
}

type Checker interface {
	Check(context.Context, CheckRequest) (CheckReport, error)
}

type LocalChecker struct {
	Dialer    *net.Dialer
	TLSConfig *tls.Config
	Timeout   time.Duration
}

func (c LocalChecker) Check(ctx context.Context, request CheckRequest) (CheckReport, error) {
	endpoint, domain, err := validateRequest(request)
	if err != nil {
		return CheckReport{}, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := c.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	connection, err := dialer.DialContext(checkCtx, "tcp", endpoint)
	if err != nil {
		return CheckReport{}, errors.New("external SOCKS endpoint is unreachable")
	}
	defer connection.Close()
	report := CheckReport{Endpoint: endpoint, TestDomain: domain, Dependency: "external_socks", ManagedBy: "external", TCPReachable: true}
	deadline := time.Now().Add(timeout)
	if value, ok := checkCtx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = connection.SetDeadline(deadline)
	if _, err := connection.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return report, errors.New("external SOCKS greeting failed")
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil || response[0] != 0x05 || response[1] != 0x00 {
		return report, errors.New("external SOCKS endpoint does not support unauthenticated SOCKS5")
	}
	report.SOCKS5Handshake = true
	requestBytes := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	requestBytes = append(requestBytes, domain...)
	requestBytes = append(requestBytes, 0x01, 0xbb)
	if _, err := connection.Write(requestBytes); err != nil {
		return report, errors.New("external SOCKS connect request failed")
	}
	if err := readConnectReply(connection); err != nil {
		return report, err
	}
	report.RemoteConnect = true
	tlsConfig := &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12}
	if c.TLSConfig != nil {
		tlsConfig = c.TLSConfig.Clone()
		tlsConfig.ServerName = domain
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	tlsConnection := tls.Client(connection, tlsConfig)
	if err := tlsConnection.HandshakeContext(checkCtx); err != nil {
		return report, errors.New("external SOCKS TLS verification failed")
	}
	report.TLSVerified = true
	if _, err := fmt.Fprintf(tlsConnection, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: FlintRoute-check\r\n\r\n", domain); err != nil {
		return report, errors.New("external SOCKS HTTP probe failed")
	}
	statusLine, err := bufio.NewReader(io.LimitReader(tlsConnection, 32<<10)).ReadString('\n')
	if err != nil {
		return report, errors.New("external SOCKS HTTP response failed")
	}
	parts := strings.Fields(statusLine)
	if len(parts) < 2 {
		return report, errors.New("external SOCKS HTTP response is invalid")
	}
	report.HTTPStatus, err = strconv.Atoi(parts[1])
	if err != nil || report.HTTPStatus < 100 || report.HTTPStatus > 599 {
		return report, errors.New("external SOCKS HTTP status is invalid")
	}
	report.Ready = true
	return report, nil
}

func validateRequest(request CheckRequest) (string, string, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(request.Endpoint))
	if err != nil {
		return "", "", errors.New("external SOCKS endpoint must use loopback host:port")
	}
	ip := net.ParseIP(host)
	port, portErr := strconv.Atoi(portText)
	if portErr != nil || port < 1 || port > 65535 || ip == nil || !ip.IsLoopback() {
		return "", "", errors.New("external SOCKS endpoint must use loopback host:port")
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(request.TestDomain), "."))
	if len(domain) < 4 || len(domain) > 253 || strings.ContainsAny(domain, "/:@ \\") || !strings.Contains(domain, ".") {
		return "", "", errors.New("test domain is invalid")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), domain, nil
}

func readConnectReply(reader io.Reader) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil || header[0] != 0x05 {
		return errors.New("external SOCKS connect response failed")
	}
	if header[1] != 0x00 {
		return errors.New("external SOCKS refused the test connection")
	}
	var addressBytes int
	switch header[3] {
	case 0x01:
		addressBytes = 4
	case 0x04:
		addressBytes = 16
	case 0x03:
		length := []byte{0}
		if _, err := io.ReadFull(reader, length); err != nil {
			return errors.New("external SOCKS connect response failed")
		}
		addressBytes = int(length[0])
	default:
		return errors.New("external SOCKS connect response has invalid address type")
	}
	if _, err := io.CopyN(io.Discard, reader, int64(addressBytes+2)); err != nil {
		return errors.New("external SOCKS connect response failed")
	}
	return nil
}
