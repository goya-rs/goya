# goya

## attach

To attach eBPF program.

Example:

```go
spec := attach.AttachmentSpec{
		Type:  "tracepoint",
		Hook1: defaultCategory,
		Hook2: defaultName,
	}
spec, err = spec.ResolveAttachment()
if err != nil {
	log.Fatalf("retrieving attachment: %s", err)
}
l, err := spec.AttachTracepoint(prog)
if err != nil {
	log.Fatalf("opening tracepoint: %s", err)
}
attachment := spec.String()
```

## ayalog

To retrieve aya logs:

```go
// Blocks until Ctrl-C (SIGINT/SIGTERM); returns nil on a clean shutdown.
if err := ayalog.Logs(coll, crateName); err != nil {
	log.Fatalf("aya log reader: %v", err)
}
```

`ayalog.LogsTo(ctx, coll, crateName, out, onErr)` is the library variant: it
takes a context, writes lines to any `io.Writer` and reports malformed
records through `onErr` instead of printing to stdout. `ayalog.NewReader`
gives full control (iterate `Entry` values yourself).

## More infos

https://github.com/goya-rs/doc
