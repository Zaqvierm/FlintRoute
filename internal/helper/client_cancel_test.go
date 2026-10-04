package helper

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestHelperCallCancellationClosesAnInflightRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skip("Unix sockets unavailable on this platform")
	}
	defer listener.Close()
	started := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var r Request
		if json.NewDecoder(conn).Decode(&r) != nil {
			return
		}
		close(started)
		_, _ = io.Copy(io.Discard, conn)
		close(closed)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := Request{ProtocolVersion: ProtocolVersion, RequestID: "cancel-test", Command: "global.status", Generation: "global", RevisionID: "global", TransactionID: "global", Global: &GlobalRequest{Operation: "status"}}
	done := make(chan error, 1)
	go func() { _, err := Call(ctx, path, r); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("helper request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("helper call ignored cancellation")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("root side was left connected after cancellation")
	}
}
