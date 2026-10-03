package api

import (
	"errors"
	"testing"
	"time"
)

func TestIdempotentDraftIsNotPublishedBeforeDurablePersistence(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	entered := make(chan struct{})
	resume := make(chan struct{})
	srv.store.SetFaultHook(func(operation string) error {
		if operation == "save_json:changes" {
			close(entered)
			<-resume
			return errors.New("injected draft persistence failure")
		}
		return nil
	})
	result := make(chan error, 1)
	go func() {
		_, _, err := srv.createDraftChangeWithRequestID("test durable intent", "test", srv.configVersion,
			[]ChangeOp{{Type: "set", Path: "/policy/route_hold_seconds", Value: 600}}, "admin", true,
			"durability-request-0001", "fingerprint")
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("draft did not reach persistence boundary")
	}
	_, visibleDuringWrite, lookupErr := srv.findIdempotentMutation("durability-request-0001", "fingerprint", "admin")
	close(resume)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("persistence failure was hidden")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("draft creation did not return after persistence failure")
	}
	srv.store.SetFaultHook(nil)
	if lookupErr != nil || visibleDuringWrite {
		t.Fatalf("retry could start an unpersisted draft: visible=%v err=%v", visibleDuringWrite, lookupErr)
	}
	if _, found, err := srv.findIdempotentMutation("durability-request-0001", "fingerprint", "admin"); err != nil || found {
		t.Fatalf("failed persistence left a replayable draft: found=%v err=%v", found, err)
	}
}

func TestConcurrentIdempotentDraftCreationPersistsOneOperation(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	entered := make(chan struct{}, 2)
	resume := make(chan struct{})
	srv.store.SetFaultHook(func(operation string) error {
		if operation == "save_json:changes" {
			entered <- struct{}{}
			<-resume
		}
		return nil
	})
	type outcome struct {
		change ChangeSet
		reused bool
		err    error
	}
	create := func(results chan<- outcome) {
		change, reused, err := srv.createDraftChangeWithRequestID("one intent", "test", 1,
			[]ChangeOp{{Type: "set", Path: "/policy/route_hold_seconds", Value: 600}}, "admin", true,
			"concurrent-request-0001", "fingerprint")
		results <- outcome{change, reused, err}
	}
	first := make(chan outcome, 1)
	second := make(chan outcome, 1)
	go create(first)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first request did not reach persistence")
	}
	go create(second)
	duplicateWrite := false
	select {
	case <-entered:
		duplicateWrite = true
	case <-time.After(100 * time.Millisecond):
	}
	close(resume)
	one, two := <-first, <-second
	srv.store.SetFaultHook(nil)
	if duplicateWrite || one.err != nil || two.err != nil || one.change.ID == "" || one.change.ID != two.change.ID || one.reused || !two.reused {
		t.Fatalf("concurrent retries created separate operations: duplicate_write=%v first=%+v second=%+v", duplicateWrite, one, two)
	}
	rows, err := srv.store.ListRaw("changes")
	if err != nil || len(rows) != 1 {
		t.Fatalf("durable operation count=%d err=%v", len(rows), err)
	}
}
