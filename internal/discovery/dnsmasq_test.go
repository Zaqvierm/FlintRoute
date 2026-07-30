package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseDNSMasqLineAcceptsOnlyClientDomainQueries(t *testing.T) {
	got, ok := ParseDNSMasqLine("Jul 30 10:00:00 dnsmasq[123]: 7 192.168.0.10/55123 query[A] ChatGPT.COM from 192.168.0.10")
	if !ok || got.Domain != "chatgpt.com" || got.QueryType != "A" {
		t.Fatalf("query was not parsed: %+v ok=%v", got, ok)
	}
	for _, line := range []string{
		"dnsmasq: reply chatgpt.com is 203.0.113.4",
		"dnsmasq: query[PTR] 4.3.2.1.in-addr.arpa from 127.0.0.1",
		"dnsmasq: query[A] localhost from 127.0.0.1",
	} {
		if _, ok := ParseDNSMasqLine(line); ok {
			t.Fatalf("non-domain observation accepted: %q", line)
		}
	}
}

func TestWatcherReadsAppendedQueriesAndHandlesTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	if err := os.WriteFile(path, []byte("dnsmasq: query[A] first.example from 192.0.2.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := make(chan string, 4)
	watcher := Watcher{Path: path, PollInterval: 5 * time.Millisecond, MaxBytes: 4096, Emit: func(_ context.Context, item Observation) {
		observed <- item.Domain
	}}
	done := make(chan error, 1)
	go func() { done <- watcher.Run(ctx) }()
	select {
	case got := <-observed:
		if got != "first.example" {
			t.Fatalf("first domain=%q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("first observation timed out")
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("dnsmasq: query[HTTPS] second.example from 192.0.2.11\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-observed:
		if got != "second.example" {
			t.Fatalf("second domain=%q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("second observation timed out")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
