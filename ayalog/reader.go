package ayalog

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// ringbufReader is the narrow interface the reader loop needs, so it can
// be tested without a kernel or a real ring buffer map.
type ringbufReader interface {
	Read() (ringbuf.Record, error)
	Close() error
}

func openRingbufReader(coll *ebpf.Collection) (ringbufReader, error) {
	logMap, ok := coll.Maps["AYA_LOGS"]
	if !ok {
		return nil, fmt.Errorf("AYA_LOGS map not found in collection")
	}
	return ringbuf.NewReader(logMap)
}

// Entry is one decoded aya-log record.
type Entry struct {
	Header  Header
	Message string
}

// Reader consumes aya-log records from an eBPF collection.
type Reader struct {
	rb       ringbufReader
	progName string
}

// NewReader opens the AYA_LOGS ring buffer of coll. If progName is
// non-empty, only records emitted by that program are delivered.
func NewReader(coll *ebpf.Collection, progName string) (*Reader, error) {
	rb, err := openRingbufReader(coll)
	if err != nil {
		return nil, err
	}
	return &Reader{rb: rb, progName: progName}, nil
}

// Run consumes records until ctx is done, the ring buffer is closed, or
// Close is called.
//
// handle receives each decoded record. If onError is non-nil, it is
// called with the error for each malformed record, which is then
// skipped. Run closes the ring buffer and returns nil on a clean
// shutdown.
func (r *Reader) Run(ctx context.Context, handle func(Entry), onError func(error)) error {
	return runReaderOn(ctx, r.rb, func(raw []byte) {
		entry, ok, err := r.decode(raw)
		if err != nil {
			if onError != nil {
				onError(err)
			}
			return
		}
		if ok {
			handle(entry)
		}
	})
}

// Close releases the ring buffer. It is also called when Run returns;
// calling Close twice is safe. Close can be used to stop a running Run.
func (r *Reader) Close() error {
	return r.rb.Close()
}

// decode splits and parses one raw record, filtering by program name.
// ok is false for records filtered out by progName (not an error).
func (r *Reader) decode(raw []byte) (entry Entry, ok bool, err error) {
	header, payload, err := splitHeaderPayload(raw)
	if err != nil {
		return Entry{}, false, err
	}
	head, err := ParseHeader(header)
	if err != nil {
		return Entry{}, false, err
	}
	if r.progName != "" && head.Target != r.progName {
		return Entry{}, false, nil
	}
	elems, err := ParsePayload(payload)
	if err != nil {
		return Entry{}, false, err
	}
	return Entry{Header: *head, Message: FormatPayload(elems)}, true, nil
}

// runReaderOn reads records from reader and forwards them to handle until
// ctx is done or the reader is closed. It must return promptly on ctx
// cancellation even if no record ever arrives.
func runReaderOn(
	ctx context.Context,
	reader ringbufReader,
	handle func(raw []byte),
) error {
	defer reader.Close()

	type readResult struct {
		record ringbuf.Record
	}
	records := make(chan readResult)
	readDone := make(chan struct{})

	go func() {
		defer close(readDone)
		for {
			record, err := reader.Read()
			if err != nil {
				// ErrClosed (or any other read error): stop the read loop;
				// the main loop below exits via readDone.
				return
			}
			if len(record.RawSample) > 0 {
				select {
				case records <- readResult{record: record}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-readDone:
			return nil
		case result := <-records:
			handle(result.record.RawSample)
		}
	}
}
