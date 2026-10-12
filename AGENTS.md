# AGENTS.md

Conventions and rules for AI agents (and humans) working on this repository.

## What this repository is

`goya` is the **Go userspace side** of an eBPF stack:

- `attach/` — attaches loaded eBPF programs (kprobe, uprobe, tracepoint, xdp, socket filter, ...) using `github.com/cilium/ebpf`.
- `ayalog/` — reads and decodes **aya-log** records (from Aya eBPF programs written in Rust) out of the `AYA_LOGS` ring buffer, and prints them.

The eBPF programs themselves are written in Rust with [Aya](https://aya.rs) in the
`goya-rs/goya-template` repo and loaded here from compiled ELF.

## Build & test commands

```sh
go build ./...
go vet ./...
gofmt -l .            # must print nothing
go test -race ./...
```

CI (`.github/workflows/ci.yml`) runs exactly these on ubuntu-latest, plus
`go test -race`. **Do not add CI matrix entries (OS, Go versions) without a
strong reason** — runner costs are a concern.

## Critical eBPF rules (programs in goya-template)

1. **Never copy from a slice with a runtime-known length inside eBPF.**
   `bpf_probe_read_user_str_bytes` / `bpf_probe_read_kernel_str_bytes` return
   `&[u8]` whose length is only known at runtime. Passing that length to a
   byte copy makes LLVM emit a call to Aya's global `memcpy`/`memset`, which
   the kernel verifier rejects (`Global function memcpy() doesn't return
   scalar`). Always use `bpf_probe_read_user_buf`/`bpf_probe_read_kernel_buf`
   with a **fixed-size** buffer (they return a scalar `Result<(), i32>`).
   See goya-template issue #35.
2. Pin Aya crates to **crates.io** releases, not `git main` (the moving API
   breaks builds).
3. Build with `strip = false` — the Go loader resolves symbols from the ELF.

## aya-log wire format (ayalog/)

**Critical:** the Go decoder must match the exact aya-log version pinned in
`goya-template` (`aya-log-ebpf` / `aya-log-common`). The wire format is
version-sensitive — verify against a real encoder dump when bumping the pin.

Format (aya-log 0.2.x), little-endian:

```
record = [size u16 LE][field]*     ; size counts the whole record incl. itself
field  = [kind u8][len u16 LE][data len bytes]
```

- The ring buffer pads the submitted entry with zeros up to the reserved
  capacity (power of two); only the first `size` bytes are meaningful.
- Header = the first six fields, in order: Target (kind 0), Level (1, one
  byte), Module (2), File (3), Line (4, u32), NumArgs (5, u32).
- Payload = the remaining fields. Text is kind 0x14 (Str). Formatted
  arguments are preceded by a DisplayHint field (kind 0, one data byte:
  1 default, 2 lower hex, 3 upper hex, 4 ip, 5 lower mac, 6 upper mac,
  7 pointer) that qualifies the following argument field (0x01-0x15).

Byte-fixture tests in `ayalog/header_parser_test.go` use records generated
with the real Rust encoder, so a format drift breaks the build.

## Error handling & robustness rules

1. **Never panic on untrusted data.** Ring buffer contents, ELF metadata and
   parsed headers come from the kernel; every parser (`ParseHeader`,
   `ParsePayload`, `FormatPayload`, ...) must bounds-check and return an
   error, not index blindly.
2. Wrap errors with `%w` so callers can use `errors.Is`/`errors.As`; use `%v`
   only for non-wrappable context.
3. The log reader must return **promptly on context cancellation** even when
   no record is in flight. `runReaderOn` (ayalog/reader.go) is the reference
   pattern: a read goroutine feeds a channel; the main loop `select`s on
   `ctx.Done()`, the read-done channel, and the records channel. No
   busy-polling, no `select { default: ... }` loops.
4. Keep the `ringbufReader` interface narrow (`Read`/`Close`) so the reader
   can be unit-tested with fakes — no kernel required.

## Testing rules

- Every binary-format parser/formatter needs **byte-fixture unit tests**
  (no BPF, no root). See `ayalog/header_parser_test.go` for the pattern
  (build the bytes the way the kernel would produce them).
- Regression tests are required for any bug fix (e.g. `TestRunReaderReturnsOnCancel`
  for the shutdown blocking bug, `TestFormatPayloadShortMacroNoPanic` for the
  unguarded `Uint32` reads).
- Tests must pass under `go test -race`. No shared state between goroutines
  without synchronization.

## Code style

- Go idioms: early returns, `fmt.Errorf` with `%w`, `context.Context` as
  first parameter for anything that can block.
- No `os.Args`/`os.Getenv` reads inside library functions — dependency
  injection or explicit parameters instead (`ResolveAttachmentWith` is the
  reference pattern; the os.Args wrapper is deprecated).
- Keep the public API of `attach` and `ayalog` small; export only what users
  of the library need.
- Don't bump `github.com/cilium/ebpf` or add new dependencies without saying
  so in the PR description (go.sum churn affects every consumer).
- Bump the Go version in `go.mod` deliberately; it sets the CI toolchain via
  `go-version-file`.

## Environment notes (this dev machine)

- `/` is nearly full: point `CARGO_HOME=/data/cargo-home` and `GOMODCACHE`
  under `/data` when building. Go lives in `/data/go/go/bin/go`.
- eBPF builds (goya-template) need: bpf-linker (prebuilt, in `~/.cargo/bin`),
  Rust nightly + `rust-src`, and `LLVM_PREFIX=/usr/lib/llvm-19`.
- Kernel 6.12; kprobe/tracepoint load+attach testing works locally.

## Release process

- `goya` consumers pin it by tag. When bumping dependencies, tag a new
  `vX.Y.Z` afterwards so `goya-template` can reference a real version
  instead of a pseudo-version.
