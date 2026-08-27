package remotefetch

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundedReadersLimitDecompressedResponses(t *testing.T) {
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	if _, err := writer.Write(bytes.Repeat([]byte{'x'}, 4096)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := ReadBounded(reader, 1024)
	if !errors.Is(err, ErrResponseTooLarge) || decompressed != nil {
		t.Fatalf("compressed response bypassed decompressed limit: bytes=%d err=%v", len(decompressed), err)
	}

	reader, err = gzip.NewReader(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var copied bytes.Buffer
	if _, err := CopyBounded(&copied, reader, 1024); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("streaming compressed response bypassed limit: bytes=%d err=%v", copied.Len(), err)
	}
}

func TestValidateURLRejectsSpecialAndPrivateTargets(t *testing.T) {
	for _, raw := range []string{
		"https://127.0.0.1/token",
		"https://10.0.0.1/token",
		"https://192.168.1.1/token",
		"https://100.64.0.1/token",
		"https://[::1]/token",
		"https://[fe80::1]/token",
	} {
		if _, err := validateURL(context.Background(), raw); err != ErrPrivateTarget {
			t.Fatalf("%s accepted or returned wrong error: %v", raw, err)
		}
	}
}

func TestNewClientRejectsNonHTTPSAndPrivateRedirectTarget(t *testing.T) {
	if _, err := NewClient(context.Background(), nil, "http://example.com", Options{}); err != ErrHTTPSRequired {
		t.Fatalf("HTTP endpoint returned %v", err)
	}
	ctx := WithLoopbackForTests(context.Background())
	client, err := NewClient(ctx, &http.Client{}, "https://127.0.0.1:443/source", Options{})
	if err != nil {
		t.Fatalf("loopback test endpoint was not enabled: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://192.168.0.1/redirect", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(request, nil); err == nil {
		t.Fatal("private redirect was accepted")
	}
}

func TestNewClientCloseIdleConnectionsClosesPinnedDialTransport(t *testing.T) {
	var closed atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed.Add(1)
		}
	}

	ctx := WithLoopbackForTests(context.Background())
	client, err := NewClient(ctx, server.Client(), server.URL+"/source", Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/source", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	client.CloseIdleConnections()

	deadline := time.Now().Add(time.Second)
	for closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if closed.Load() == 0 {
		t.Fatal("CloseIdleConnections left the pinned dial transport connection open")
	}
}
