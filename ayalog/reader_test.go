package ayalog

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// blockingReader simulates a ring buffer that never produces a record:
// Read blocks until Close is called.
type blockingReader struct {
	closeCh chan struct{}
	closed  bool
}

func newBlockingReader() *blockingReader {
	return &blockingReader{closeCh: make(chan struct{})}
}

func (r *blockingReader) Read() (ringbuf.Record, error) {
	<-r.closeCh
	return ringbuf.Record{}, ringbuf.ErrClosed
}

func (r *blockingReader) Close() error {
	if !r.closed {
		r.closed = true
		close(r.closeCh)
	}
	return nil
}

// chanReader emits the given records and then blocks until closed.
type chanReader struct {
	records []ringbuf.Record
	idx     int
	closeCh chan struct{}
	closed  bool
}

func newChanReader(records ...ringbuf.Record) *chanReader {
	return &chanReader{records: records, closeCh: make(chan struct{})}
}

func (r *chanReader) Read() (ringbuf.Record, error) {
	if r.idx < len(r.records) {
		rec := r.records[r.idx]
		r.idx++
		return rec, nil
	}
	<-r.closeCh
	return ringbuf.Record{}, ringbuf.ErrClosed
}

func (r *chanReader) Close() error {
	if !r.closed {
		r.closed = true
		close(r.closeCh)
	}
	return nil
}

// TestRunReaderReturnsOnCancel is the regression test for B1: the previous
// select-with-default loop blocked in reader.Read() after Ctrl-C and only
// returned when the next log arrived. runReaderOn must return promptly on
// context cancellation even with a silent ring buffer.
func TestRunReaderReturnsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader := newBlockingReader()
	done := make(chan error, 1)
	go func() { done <- runReaderOn(ctx, reader, nil) }()

	// Give the read goroutine a moment to block in Read().
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runReaderOn returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runReaderOn did not return promptly after context cancellation")
	}
}

func TestRunReaderForwardsRecords(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader := newChanReader(
		ringbuf.Record{RawSample: []byte("hello ")},
		ringbuf.Record{RawSample: []byte("world")},
	)

	var mu sync.Mutex
	var got []byte
	allReceived := make(chan struct{})
	closeOnce := sync.Once{}

	done := make(chan error, 1)
	go func() {
		done <- runReaderOn(ctx, reader, func(raw []byte) {
			mu.Lock()
			got = append(got, raw...)
			n := len(got)
			mu.Unlock()
			if n == len("hello world") {
				closeOnce.Do(func() { close(allReceived) })
			}
		})
	}()

	select {
	case <-allReceived:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("timed out waiting for records to be forwarded")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runReaderOn returned error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if string(got) != "hello world" {
		t.Fatalf("handler received %q, want %q", got, "hello world")
	}
}

func TestRunReaderIgnoresEmptyRecords(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader := newChanReader(
		ringbuf.Record{RawSample: []byte{}},
		ringbuf.Record{RawSample: []byte("x")},
	)

	var mu sync.Mutex
	var got []byte
	received := make(chan struct{})
	closeOnce := sync.Once{}

	done := make(chan error, 1)
	go func() {
		done <- runReaderOn(ctx, reader, func(raw []byte) {
			mu.Lock()
			got = append(got, raw...)
			mu.Unlock()
			closeOnce.Do(func() { close(received) })
		})
	}()

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("timed out waiting for record to be forwarded")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runReaderOn returned error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if string(got) != "x" {
		t.Fatalf("handler received %q, want %q", got, "x")
	}
}
