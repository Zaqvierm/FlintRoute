package externalsocks

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckVerifiesCompleteSOCKSPath(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer target.Close()
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	done := make(chan error, 1)
	go func() {
		client, err := proxy.Accept()
		if err != nil {
			done <- err
			return
		}
		defer client.Close()
		greeting := make([]byte, 3)
		if _, err = io.ReadFull(client, greeting); err != nil {
			done <- err
			return
		}
		_, _ = client.Write([]byte{5, 0})
		header := make([]byte, 5)
		if _, err = io.ReadFull(client, header); err != nil {
			done <- err
			return
		}
		remaining := make([]byte, int(header[4])+2)
		if _, err = io.ReadFull(client, remaining); err != nil {
			done <- err
			return
		}
		upstream, err := net.Dial("tcp", target.Listener.Addr().String())
		if err != nil {
			done <- err
			return
		}
		defer upstream.Close()
		_, _ = client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
		go func() { _, _ = io.Copy(upstream, client) }()
		_, err = io.Copy(client, upstream)
		done <- err
	}()
	report, err := (LocalChecker{Timeout: 2 * time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true}}).Check(context.Background(), CheckRequest{Endpoint: proxy.Addr().String(), TestDomain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready || !report.TCPReachable || !report.SOCKS5Handshake || !report.RemoteConnect || !report.TLSVerified || report.HTTPStatus != http.StatusNoContent {
		t.Fatalf("incomplete check report: %+v", report)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCheckRejectsNonLoopbackEndpoint(t *testing.T) {
	_, err := (LocalChecker{}).Check(context.Background(), CheckRequest{Endpoint: "192.0.2.10:1180", TestDomain: "example.com"})
	if err == nil {
		t.Fatal("non-loopback SOCKS endpoint was accepted")
	}
}

func TestCheckReportsUnreachableEndpointWithoutClaimingReadiness(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listener.Addr().String()
	_ = listener.Close()
	report, err := (LocalChecker{Timeout: 100 * time.Millisecond}).Check(context.Background(), CheckRequest{Endpoint: endpoint, TestDomain: "example.com"})
	if err == nil || report.Ready {
		t.Fatalf("unreachable endpoint was accepted: report=%+v err=%v", report, err)
	}
}

func TestReadConnectReply(t *testing.T) {
	if err := readConnectReply(&oneByteReader{data: []byte{5, 0, 0, 1, 127, 0, 0, 1, 4, 156}}); err != nil {
		t.Fatal(err)
	}
	if err := readConnectReply(&oneByteReader{data: []byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}}); err == nil {
		t.Fatal("SOCKS refusal was accepted")
	}
}

type oneByteReader struct{ data []byte }

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, context.Canceled
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}
