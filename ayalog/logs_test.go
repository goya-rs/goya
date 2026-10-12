package ayalog

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// record wraps raw bytes in a ring buffer record for the test readers.
func record(raw []byte) ringbuf.Record {
	return ringbuf.Record{RawSample: raw}
}

// waitEntry blocks until the handler delivers an entry or the deadline
// passes. It returns the first entry and whether the handler was called.
func waitEntry(t *testing.T, got chan Entry, d time.Duration) (Entry, bool) {
	t.Helper()
	select {
	case e := <-got:
		return e, true
	case <-time.After(d):
		return Entry{}, false
	}
}

func TestReaderRunDeliversEntries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	raw, err := hex.DecodeString(recordF5)
	if err != nil {
		t.Fatal(err)
	}
	reader := &Reader{
		rb:       newChanReader(record(raw)),
		progName: "demo",
	}

	got := make(chan Entry, 1)
	done := make(chan error, 1)
	go func() { done <- reader.Run(ctx, func(e Entry) { got <- e }, nil) }()

	e, ok := waitEntry(t, got, 2*time.Second)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !ok {
		t.Fatal("handler was not called")
	}
	if e.Header.Target != "demo" || e.Header.Line != 40 {
		t.Errorf("header = %+v, want target demo line 40", e.Header)
	}
	if e.Message != "plain text" {
		t.Errorf("Message = %q, want %q", e.Message, "plain text")
	}
}

// TestReaderRunFiltersByProgName ensures records from other programs are
// dropped silently (not an error).
func TestReaderRunFiltersByProgName(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	raw, _ := hex.DecodeString(recordF5) // target "demo"
	reader := &Reader{
		rb:       newChanReader(record(raw)),
		progName: "other_prog",
	}

	var mu sync.Mutex
	var calls, errCalls int
	done := make(chan error, 1)
	go func() {
		done <- reader.Run(ctx, func(Entry) {
			mu.Lock()
			calls++
			mu.Unlock()
		}, func(error) {
			mu.Lock()
			errCalls++
			mu.Unlock()
		})
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 || errCalls != 0 {
		t.Errorf("calls=%d errCalls=%d, want 0/0 (filtered out)", calls, errCalls)
	}
}

// TestReaderRunReportsMalformed ensures a garbage record goes to onError,
// not to the handler, and does not stop the reader.
func TestReaderRunReportsMalformed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	raw, _ := hex.DecodeString(recordF5)
	garbage := record([]byte{0x00, 0xff, 0x13, 0x37}) // size 0x3713 > record

	var mu sync.Mutex
	var calls, errCalls int
	var firstErr error
	done := make(chan error, 1)
	reader := &Reader{
		rb:       newChanReader(garbage, record(raw)),
		progName: "demo",
	}
	go func() {
		done <- reader.Run(ctx,
			func(Entry) {
				mu.Lock()
				calls++
				mu.Unlock()
			},
			func(err error) {
				mu.Lock()
				errCalls++
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := calls == 1 && errCalls == 1
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 || errCalls != 1 {
		t.Errorf("calls=%d errCalls=%d, want 1/1", calls, errCalls)
	}
	if firstErr == nil {
		t.Error("onError was not called with an error")
	}
}

func TestNewReaderMissingMap(t *testing.T) {
	// An empty collection loads fine and has no AYA_LOGS map.
	coll, err := ebpf.NewCollection(&ebpf.CollectionSpec{})
	if err != nil {
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()

	if _, err := NewReader(coll, "demo"); err == nil {
		t.Fatal("NewReader should fail when AYA_LOGS is missing")
	} else if !strings.Contains(err.Error(), "AYA_LOGS") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLogsToMissingMap(t *testing.T) {
	coll, err := ebpf.NewCollection(&ebpf.CollectionSpec{})
	if err != nil {
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var buf bytes.Buffer
	if err := LogsTo(ctx, coll, "demo", &buf, nil); err == nil {
		t.Fatal("LogsTo should fail when AYA_LOGS is missing")
	}
}

func TestFormatLogLine(t *testing.T) {
	cases := []struct {
		head Header
		msg  string
		want string
	}{
		{Header{Target: "demo", Level: LogInfo, File: "main.rs"}, "hello",
			"[INFO  demo] hello"},
		{Header{Target: "demo", Level: LogError, File: "src/foo.rs"}, "boom",
			"[ERROR  demo::foo] boom"},
		{Header{Target: "demo", Level: LogTrace, File: "main"}, "t",
			"[TRACE  demo] t"},
	}
	for _, c := range cases {
		if got := formatLogLine(&c.head, c.msg); got != c.want {
			t.Errorf("formatLogLine(%+v, %q) = %q, want %q", c.head, c.msg, got, c.want)
		}
	}
}
