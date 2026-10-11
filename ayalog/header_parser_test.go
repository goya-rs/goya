package ayalog

import (
	"encoding/binary"
	"testing"
)

// buildHeader assembles a TLV-encoded aya-log header the same way the
// kernel-side aya-log produces it:
//
//	[0] = 0x04 (padding)
//	[1..] = segments, each: <len byte> 0x00 <data>
//
// Segments, in order: target, level (1 byte), module, file, line (u32 LE),
// num_args (u32 LE).
func buildHeader(target, module, file string, level LogLevel, line, numArgs uint32) []byte {
	seg := func(data []byte) []byte {
		out := []byte{byte(len(data)), 0x00}
		return append(out, data...)
	}
	var h []byte
	h = append(h, 0x04)
	h = append(h, seg([]byte(target))...)
	h = append(h, seg([]byte{byte(level)})...)
	h = append(h, seg([]byte(module))...)
	h = append(h, seg([]byte(file))...)
	var u32b [4]byte
	binary.LittleEndian.PutUint32(u32b[:], line)
	h = append(h, seg(u32b[:])...)
	binary.LittleEndian.PutUint32(u32b[:], numArgs)
	h = append(h, seg(u32b[:])...)
	return h
}

func TestParseHeaderValid(t *testing.T) {
	h := buildHeader("test_prog", "module_a", "main.rs", LogInfo, 42, 3)

	parsed, err := ParseHeader(h)
	if err != nil {
		t.Fatalf("ParseHeader returned error: %v", err)
	}
	if parsed.Target != "test_prog" {
		t.Errorf("Target = %q, want %q", parsed.Target, "test_prog")
	}
	if parsed.Level != LogInfo {
		t.Errorf("Level = %v, want %v", parsed.Level, LogInfo)
	}
	if parsed.Module != "module_a" {
		t.Errorf("Module = %q, want %q", parsed.Module, "module_a")
	}
	if parsed.File != "main.rs" {
		t.Errorf("File = %q, want %q", parsed.File, "main.rs")
	}
	if parsed.Line != 42 {
		t.Errorf("Line = %d, want 42", parsed.Line)
	}
	if parsed.NumArgs != 3 {
		t.Errorf("NumArgs = %d, want 3", parsed.NumArgs)
	}
}

func TestParseHeaderLevelAllValues(t *testing.T) {
	for _, level := range []LogLevel{LogError, LogWarn, LogInfo, LogDebug, LogTrace} {
		h := buildHeader("p", "m", "f", level, 1, 0)
		parsed, err := ParseHeader(h)
		if err != nil {
			t.Fatalf("ParseHeader(%v) error: %v", level, err)
		}
		if parsed.Level != level {
			t.Errorf("Level = %v, want %v", parsed.Level, level)
		}
	}
}

func TestParseHeaderTruncatedReturnsError(t *testing.T) {
	// A full header cut in half: must return an error, not panic (B2).
	full := buildHeader("test_prog", "module_a", "main.rs", LogInfo, 42, 3)
	half := full[:len(full)/2]

	if _, err := ParseHeader(half); err == nil {
		t.Fatal("ParseHeader(truncated) should return an error")
	}
}

func TestParseHeaderEmpty(t *testing.T) {
	if _, err := ParseHeader(nil); err == nil {
		t.Fatal("ParseHeader(nil) should return an error")
	}
	if _, err := ParseHeader([]byte{}); err == nil {
		t.Fatal("ParseHeader([]) should return an error")
	}
}

func TestParseHeaderShortLineSegment(t *testing.T) {
	// Craft a header whose "line" segment is only 2 bytes instead of 4:
	// must error, not panic (B2).
	var h []byte
	h = append(h, 0x04)
	seg := func(data []byte) {
		h = append(h, byte(len(data)), 0x00)
		h = append(h, data...)
	}
	seg([]byte("p"))        // target
	seg([]byte{3})          // level
	seg([]byte("m"))        // module
	seg([]byte("f"))        // file
	seg([]byte{0x01, 0x02}) // line: only 2 bytes -> error

	if _, err := ParseHeader(h); err == nil {
		t.Fatal("ParseHeader with a 2-byte line segment should return an error")
	}
}

func TestParseHeaderEmptyLevelSegment(t *testing.T) {
	// Target then an empty level segment (len byte 0 handled as padding),
	// so we only have fewer than 6 real segments.
	var h []byte
	h = append(h, 0x04)
	h = append(h, 0x01, 0x00, 'p') // target "p"
	// level segment omitted entirely: only 1 segment total.
	if _, err := ParseHeader(h); err == nil {
		t.Fatal("ParseHeader with 1 segment should return an error")
	}
}
