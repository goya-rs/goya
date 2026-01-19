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

```
ayalog.Logs(coll, crateName)
```

## More infos

https://github.com/goya-rs/doc
