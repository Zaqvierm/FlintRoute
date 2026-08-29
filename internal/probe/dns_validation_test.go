package probe

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/miekg/dns"
)

func TestValidateDNSResolverTransportUsesExactUDPAndTCP(t *testing.T) {
	udpServer, closeUDP := startValidationUDPServer(t)
	defer closeUDP()
	udp, err := validateDNSResolverTransport(context.Background(), udpServer, "example.com", "udp", true)
	if err != nil || !udp.Safe || udp.AAnswers != 1 || udp.Transport != "udp" {
		t.Fatalf("UDP resolver validation failed: result=%+v err=%v", udp, err)
	}

	tcpServer, closeTCP := startTCPDNSServer(t)
	defer closeTCP()
	tcp, err := validateDNSResolverTransport(context.Background(), tcpServer, "example.com", "tcp", true)
	if err != nil || !tcp.Safe || tcp.AAnswers != 1 || tcp.AAAAAnswers != 1 || tcp.Transport != "tcp" {
		t.Fatalf("TCP resolver validation failed: result=%+v err=%v", tcp, err)
	}
}

func startValidationUDPServer(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
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
	server := &dns.Server{PacketConn: conn, Net: "udp", Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	return conn.LocalAddr().String(), func() { _ = server.Shutdown() }
}

func TestValidateDNSResolverTransportRejectsPrivateProductionEndpoint(t *testing.T) {
	if _, err := ValidateDNSResolverTransport(context.Background(), "127.0.0.1:53", "example.com", "udp"); err == nil {
		t.Fatal("private production resolver endpoint was accepted")
	}
}

func TestSmartDNSValidationDoesNotTreatAuthOrWAFAsApplicationProof(t *testing.T) {
	for _, status := range []string{"AUTH_REQUIRED", "WAF_OR_RATE_LIMIT", "REGION_BLOCK"} {
		if smartDNSApplicationProofAccepted(RouteResult{
			Status: status, ServiceOK: false,
		}) {
			t.Fatalf("status %s was accepted as Smart DNS application proof", status)
		}
	}
	if smartDNSApplicationProofAccepted(RouteResult{
		Status: "OK", ServiceOK: true,
	}) == false {
		t.Fatal("a fully verified OK route was rejected")
	}
}

func TestSmartDNSValidationExpectedCodesExcludeErrorClasses(t *testing.T) {
	codes := smartDNSValidationExpectedCodes()
	for _, forbidden := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusTooManyRequests} {
		for _, code := range codes {
			if code == forbidden {
				t.Fatalf("HTTP %d must not be a Smart DNS validation success code", forbidden)
			}
		}
	}
}
