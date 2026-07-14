package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"router-policy/internal/config"
)

func TestSOCKSRemoteDNSUsesSameProxyAndReturnsConnectableIPs(t *testing.T) {
	dnsAddress, stopDNS := startTCPDNSServer(t)
	defer stopDNS()
	proxyAddress, proxy := startSOCKSForwarder(t)
	defer proxy.Close()
	cfg := &config.Config{Platform: config.Platform{Target: "test"}}
	route := config.Route{Type: "vless", Tag: "vless-a", SOCKS5: proxyAddress, DNSServer: dnsAddress, DNSMode: "socks_remote"}
	addresses, resolver, protocol, err := resolveForRoute(context.Background(), cfg, route, "service.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 || resolver != "socks5:"+dnsAddress || protocol != "socks5_tcp" {
		t.Fatalf("unexpected SOCKS DNS result: addresses=%v resolver=%q protocol=%q", addresses, resolver, protocol)
	}
	proxy.mu.Lock()
	targets := append([]string(nil), proxy.targets...)
	proxy.mu.Unlock()
	if len(targets) != 2 || targets[0] != dnsAddress || targets[1] != dnsAddress {
		t.Fatalf("DNS did not traverse the configured SOCKS path: %v", targets)
	}
}

func startTCPDNSServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		if len(request.Question) == 1 {
			switch request.Question[0].Qtype {
			case dns.TypeA:
				response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.55")})
			case dns.TypeAAAA:
				response.Answer = append(response.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::55")})
			}
		}
		_ = writer.WriteMsg(response)
	})
	server := &dns.Server{Listener: listener, Net: "tcp", Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	return listener.Addr().String(), func() { _ = server.Shutdown() }
}

type socksForwarder struct {
	listener net.Listener
	mu       sync.Mutex
	targets  []string
}

func startSOCKSForwarder(t *testing.T) (string, *socksForwarder) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &socksForwarder{listener: listener}
	go proxy.serve()
	return listener.Addr().String(), proxy
}

func (s *socksForwarder) Close() { _ = s.listener.Close() }

func (s *socksForwarder) serve() {
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(connection)
	}
}

func (s *socksForwarder) handle(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	greeting := make([]byte, 3)
	if _, err := io.ReadFull(client, greeting); err != nil || greeting[0] != 5 {
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(client, header); err != nil || header[0] != 5 || header[1] != 1 {
		return
	}
	var host string
	switch header[3] {
	case 1:
		address := make([]byte, 4)
		if _, err := io.ReadFull(client, address); err != nil {
			return
		}
		host = net.IP(address).String()
	case 4:
		address := make([]byte, 16)
		if _, err := io.ReadFull(client, address); err != nil {
			return
		}
		host = net.IP(address).String()
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(client, length); err != nil {
			return
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(client, address); err != nil {
			return
		}
		host = string(address)
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(client, portBytes); err != nil {
		return
	}
	target := net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(portBytes)))
	upstream, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	s.mu.Lock()
	s.targets = append(s.targets, target)
	s.mu.Unlock()
	if _, err := client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	go func() { _, _ = io.Copy(upstream, client); _ = upstream.(*net.TCPConn).CloseWrite() }()
	_, _ = io.Copy(client, upstream)
}
