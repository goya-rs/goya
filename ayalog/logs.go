package ayalog

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
)

// Logs listens for aya-log records and prints them to stdout until the
// process receives SIGINT or SIGTERM. It returns the error, if any, from
// reading the ring buffer (a clean shutdown on Ctrl-C is nil).
//
// It is a convenience wrapper around LogsTo for the common case.
func Logs(coll *ebpf.Collection, progName string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Println("Listening to Aya logs...")
	fmt.Println("Waiting for Ctrl-C.")

	err := LogsTo(ctx, coll, progName, os.Stdout, func(err error) {
		log.Println(err)
	})

	fmt.Println("Shutting down...")
	return err
}

// LogsTo runs the log reader on ctx and writes one line per record to out.
//
// Malformed records are reported through onErr (if non-nil) and skipped.
// Returns nil on a clean shutdown (ctx done or ring buffer closed).
func LogsTo(ctx context.Context, coll *ebpf.Collection, progName string, out io.Writer, onErr func(error)) error {
	reader, err := NewReader(coll, progName)
	if err != nil {
		return err
	}
	defer reader.Close()

	return reader.Run(ctx, func(e Entry) {
		fmt.Fprintln(out, formatLogLine(&e.Header, e.Message))
	}, func(err error) {
		if onErr != nil {
			onErr(err)
		}
	})
}
