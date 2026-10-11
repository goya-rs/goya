package ayalog

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// ringbufReader is the narrow interface runReader needs, so it can be
// tested without a kernel or a real ring buffer map.
type ringbufReader interface {
	Read() (ringbuf.Record, error)
	Close() error
}

func runReader(
	ctx context.Context,
	coll *ebpf.Collection,
	handle func(raw []byte),
) error {
	reader, err := openRingbufReader(coll)
	if err != nil {
		return err
	}
	return runReaderOn(ctx, reader, handle)
}

func openRingbufReader(coll *ebpf.Collection) (ringbufReader, error) {
	logMap, ok := coll.Maps["AYA_LOGS"]
	if !ok {
		return nil, fmt.Errorf("AYA_LOGS map not found")
	}
	return ringbuf.NewReader(logMap)
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
