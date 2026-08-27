package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

func TestWatcherStartAtEndSkipsHistoricalLogAndReadsNewQueries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	if err := os.WriteFile(path, []byte("dnsmasq: query[A] historical.example from 192.0.2.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := make(chan string, 4)
	watcher := Watcher{Path: path, PollInterval: 5 * time.Millisecond, MaxBytes: 4096, StartAtEnd: true, Emit: func(_ context.Context, item Observation) {
		observed <- item.Domain
	}}
	done := make(chan error, 1)
	go func() { done <- watcher.Run(ctx) }()
	select {
	case got := <-observed:
		t.Fatalf("historical observation replayed on startup: %q", got)
	case <-time.After(100 * time.Millisecond):
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("dnsmasq: query[HTTPS] fresh.example from 192.0.2.11\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-observed:
		if got != "fresh.example" {
			t.Fatalf("new domain=%q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("new observation timed out")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWatcherNeverTruncatesWriterOwnedOversizedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	content := make([]byte, 0, 128)
	for i := 0; i < 20; i++ {
		content = append(content, []byte("dnsmasq: query[A] oversized.example from 192.0.2.10\n")...)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	watcher := Watcher{Path: path, MaxBytes: 32, Emit: func(context.Context, Observation) {}}
	if _, _, err := watcher.readFrom(context.Background(), 0, 32); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(len(content)) {
		t.Fatalf("reader truncated dnsmasq-owned log: got %d want %d", info.Size(), len(content))
	}
}

func TestWatcherDetectsRecreatedLogByIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	first := "dnsmasq: query[A] first.example from 192.0.2.10\n"
	if err := os.WriteFile(path, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	if identity := observationFileIdentityFromPath(t, path); identity == "" {
		t.Skip("host does not expose a stable device/inode identity")
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

	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	// Keep the replacement at least as large as the old file.  Size-only
	// cursors would incorrectly continue in the middle and miss this query.
	second := "dnsmasq: query[HTTPS] second.example from 192.0.2.11\n"
	if len(second) < len(first) {
		second = strings.Repeat("x", len(first)-len(second)) + second
	}
	if err := os.WriteFile(path, []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-observed:
		if got != "second.example" {
			t.Fatalf("replacement domain=%q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement observation timed out")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWatcherDrainsOversizedHistoricalLogAndReachesFreshTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	line := "dnsmasq: query[A] historical.example from 192.0.2.10\n"
	count := (12<<20)/len(line) + 1
	var content strings.Builder
	content.Grow(count * len(line))
	for i := 0; i < count; i++ {
		content.WriteString(line)
	}
	content.WriteString("dnsmasq: query[HTTPS] fresh-tail.example from 192.0.2.11\n")
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	var fresh int
	watcher := Watcher{Path: path, MaxBytes: 1 << 20, Emit: func(_ context.Context, item Observation) {
		if item.Domain == "fresh-tail.example" {
			fresh++
		}
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var offset int64
	for offset < int64(len(content.String())) {
		next, _, err := watcher.readFrom(ctx, offset, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if next <= offset {
			t.Fatalf("bounded reader made no progress at %d/%d", offset, len(content.String()))
		}
		offset = next
	}
	if fresh != 1 {
		t.Fatalf("fresh tail emitted %d times, want exactly once", fresh)
	}
}

func TestWatcherDoesNotPersistCursorInsideChunkBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	line := "dnsmasq: query[A] chunk.example from 192.0.2.10\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	var observed int
	watcher := Watcher{Path: path, MaxBytes: int64(strings.IndexByte(line, '\n')), Emit: func(context.Context, Observation) { observed++ }}
	offset, _, err := watcher.readFrom(context.Background(), 0, watcher.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 0 || observed != 0 {
		t.Fatalf("partial line advanced cursor: offset=%d observations=%d", offset, observed)
	}
	offset, _, err = watcher.readFrom(context.Background(), offset, int64(len(line)))
	if err != nil {
		t.Fatal(err)
	}
	if offset != int64(len(line)) || observed != 1 {
		t.Fatalf("complete line was not emitted after continuation: offset=%d observations=%d", offset, observed)
	}
}

func TestWatcherAppendLargerThanBoundedPassReachesTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	if err := os.WriteFile(path, []byte("dnsmasq: query[A] first.example from 192.0.2.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var fresh int
	watcher := Watcher{Path: path, MaxBytes: 1 << 20, Emit: func(_ context.Context, item Observation) {
		if item.Domain == "appended-tail.example" {
			fresh++
		}
	}}
	initial, _, err := watcher.readFrom(context.Background(), 0, watcher.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40000; i++ {
		if _, err := f.WriteString("dnsmasq: query[A] appended-" + strconv.Itoa(i) + ".example from 192.0.2.10\n"); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if _, err := f.WriteString("dnsmasq: query[HTTPS] appended-tail.example from 192.0.2.10\n"); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	offset := initial
	for offset < info.Size() {
		next, _, err := watcher.readFrom(context.Background(), offset, watcher.MaxBytes)
		if err != nil {
			t.Fatal(err)
		}
		if next <= offset {
			t.Fatalf("append drain stalled at %d/%d", offset, info.Size())
		}
		offset = next
	}
	if fresh != 1 {
		t.Fatalf("appended tail emitted %d times, want once", fresh)
	}
}

func TestWatcherDrainsOversizedMalformedLineWithoutLoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	bad := strings.Repeat("x", 512<<10)
	content := bad + "\n" + "dnsmasq: query[A] after-malformed.example from 192.0.2.10\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var observed int
	watcher := Watcher{Path: path, MaxBytes: 1 << 20, Emit: func(_ context.Context, item Observation) {
		if item.Domain == "after-malformed.example" {
			observed++
		}
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var offset int64
	for offset < int64(len(content)) {
		next, _, err := watcher.readFrom(ctx, offset, watcher.MaxBytes)
		if err != nil {
			t.Fatal(err)
		}
		if next <= offset {
			t.Fatalf("malformed line drain stalled at %d", offset)
		}
		offset = next
	}
	if observed != 1 {
		t.Fatalf("valid record after malformed line emitted %d times", observed)
	}
}

func TestWatcherDrainsPathologicalLineBeyondPassBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	content := strings.Repeat("x", 2<<20) + "\n" + "dnsmasq: query[A] after-pathological.example from 192.0.2.10\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var observed int
	watcher := Watcher{Path: path, MaxBytes: 1 << 20, Emit: func(_ context.Context, item Observation) {
		if item.Domain == "after-pathological.example" {
			observed++
		}
	}}
	var offset int64
	for offset < int64(len(content)) {
		next, _, err := watcher.readFrom(context.Background(), offset, watcher.MaxBytes)
		if err != nil {
			t.Fatal(err)
		}
		if next <= offset {
			t.Fatalf("pathological line pinned the cursor at %d", offset)
		}
		offset = next
	}
	if observed != 1 {
		t.Fatalf("valid record after pathological line emitted %d times", observed)
	}
}

func TestWatcherDoesNotLoopOnUnterminatedOversizedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 9<<20)), 0o600); err != nil {
		t.Fatal(err)
	}
	watcher := Watcher{Path: path, MaxBytes: 1 << 20, Emit: func(context.Context, Observation) {}}
	first, _, err := watcher.readFrom(context.Background(), 0, watcher.MaxBytes)
	if err != nil || first <= 0 {
		t.Fatalf("unterminated oversized line made no bounded progress: offset=%d err=%v", first, err)
	}
	second, _, err := watcher.readFrom(context.Background(), first, watcher.MaxBytes)
	if err != nil || second <= first {
		t.Fatalf("discarded malformed tail was rewound or pinned: first=%d second=%d err=%v", first, second, err)
	}
}

func TestWatcherDoesNotDuplicateStableTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.log")
	if err := os.WriteFile(path, []byte("dnsmasq: query[A] stable.example from 192.0.2.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var observed int
	watcher := Watcher{Path: path, MaxBytes: 4096, Emit: func(context.Context, Observation) { observed++ }}
	offset, _, err := watcher.readFrom(context.Background(), 0, watcher.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := watcher.readFrom(context.Background(), offset, watcher.MaxBytes); err != nil {
		t.Fatal(err)
	}
	if observed != 1 {
		t.Fatalf("stable tail emitted %d times, want one", observed)
	}
}

func observationFileIdentityFromPath(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return observationFileIdentity(info)
}
