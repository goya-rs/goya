package ayalog

import (
	"encoding/hex"
	"testing"
)

// Real aya-log 0.2.0 records, generated with the actual Rust encoder
// (aya-log-common 0.2.0) so the fixtures match the wire format byte for
// byte. Each record is [size u16 LE][six header fields][payload fields].
const (
	// "hello " + {:x} 0x1234 + ptr(0xdeadbeef) + "world", line 42, num_args 3
	recordF1 = "5a00" +
		"000b006b70726f62655f64656d6f" + // Target "kprobe_demo"
		"01010003" + // Level Info
		"02040064656d6f" + // Module "demo"
		"0307006d61696e2e7273" + // File "main.rs"
		"0404002a000000" + // Line 42
		"05040003000000" + // NumArgs 3
		"14060068656c6c6f20" + // text "hello "
		"00010002" + // DisplayHint LowerHex
		"08040034120000" + // U32 0x1234
		"150800efbeadde00000000" + // Pointer 0xdeadbeef
		"140500776f726c64" // text "world"

	// {} -42i32 + {} 200u8 + {} u64::MAX, line 10
	recordF2 = "4e00" +
		"00040064656d6f" + "01010003" + "02040064656d6f" + "0307006d61696e2e7273" +
		"0404000a000000" + "05040003000000" +
		"00010001030400d6ffffff" + // Default, I32 -42
		"00010001060100c8" + // Default, U8 200
		"00010001090800ffffffffffffffff" // Default, U64 max

	// {:i} 192.168.1.10 + {:i} 2001:db8::ff00:42 + {:mac} + {:MAC}, line 20
	recordF3 = "6800" +
		"00040064656d6f" + "01010003" + "02040064656d6f" + "0307006d61696e2e7273" +
		"04040014000000" + "05040004000000" +
		"000100040d0400c0a8010a" + // Ip, Ipv4Addr
		"000100040e100020010db80000000000000000ff000042" + // Ip, Ipv6Addr
		"00010005100600deadbeef0001" + // LowerMac, ArrU8Len6
		"00010006100600deadbeef0001" // UpperMac, ArrU8Len6

	// {:X} 0xABCDu16 + {} 3.14f64, line 30
	recordF4 = "4400" +
		"00040064656d6f" + "01010003" + "02040064656d6f" + "0307006d61696e2e7273" +
		"0404001e000000" + "05040002000000" +
		"00010003070200cdab" + // UpperHex, U16 0xABCD
		"000100010c08001f85eb51b81e0940" // Default, F64 3.14

	// "plain text", line 40
	recordF5 = "3900" +
		"00040064656d6f" + "01010003" + "02040064656d6f" + "0307006d61696e2e7273" +
		"04040028000000" + "05040001000000" +
		"140a00706c61696e2074657874"
)

// padRecord pads a record (as produced by the Rust encoder) with zeros up
// to capacity, like the ring buffer does (capacity is a power of two).
func padRecord(t *testing.T, hexRecord string, capacity int) []byte {
	t.Helper()
	raw, err := hex.DecodeString(hexRecord)
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	if capacity < len(raw) {
		t.Fatalf("capacity %d smaller than record %d", capacity, len(raw))
	}
	padded := make([]byte, capacity)
	copy(padded, raw)
	return padded
}

// decode runs the full pipeline (split, header, payload, format) on a raw
// ring buffer record, like logs.go does.
func decode(t *testing.T, raw []byte) (*Header, string) {
	t.Helper()
	header, payload, err := splitHeaderPayload(raw)
	if err != nil {
		t.Fatalf("splitHeaderPayload: %v", err)
	}
	head, err := ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	elems, err := ParsePayload(payload)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	return head, FormatPayload(elems)
}

func TestDecodeRealRecords(t *testing.T) {
	cases := []struct {
		name   string
		record string
		cap    int
		line   uint32
		msg    string
	}{
		{"text hex ptr text", recordF1, 128, 42, "hello 12340xdeadbeefworld"},
		{"integers", recordF2, 128, 10, "-4220018446744073709551615"},
		{"ip mac", recordF3, 128, 20, "192.168.1.102001:db8::ff00:42de:ad:be:ef:00:01DE:AD:BE:EF:00:01"},
		{"upper hex float", recordF4, 128, 30, "ABCD3.14"},
		{"text only", recordF5, 64, 40, "plain text"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := padRecord(t, c.record, c.cap)
			head, msg := decode(t, raw)

			if head.Target != "kprobe_demo" && head.Target != "demo" {
				t.Errorf("Target = %q, want demo/kprobe_demo", head.Target)
			}
			if head.Level != LogInfo {
				t.Errorf("Level = %v, want Info", head.Level)
			}
			if head.File != "main.rs" {
				t.Errorf("File = %q, want main.rs", head.File)
			}
			if head.Line != c.line {
				t.Errorf("Line = %d, want %d", head.Line, c.line)
			}
			if msg != c.msg {
				t.Errorf("FormatPayload = %q, want %q", msg, c.msg)
			}
		})
	}
}

// TestDecodeNoPadding ensures the size field alone bounds the record when
// the ring buffer happens to submit it unpadded.
func TestDecodeNoPadding(t *testing.T) {
	raw, err := hex.DecodeString(recordF5)
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	_, msg := decode(t, raw)
	if msg != "plain text" {
		t.Errorf("FormatPayload = %q, want %q", msg, "plain text")
	}
}

// TestDecodeTruncatedRecord ensures a record cut in half is rejected with
// an error, not a panic.
func TestDecodeTruncatedRecord(t *testing.T) {
	raw := padRecord(t, recordF1, 128)
	half := raw[:len(raw)/2]

	if _, _, err := splitHeaderPayload(half); err == nil {
		// The split may succeed if the header is intact; the payload must
		// then fail to parse.
		_, payload, _ := splitHeaderPayload(half)
		if _, err := ParsePayload(payload); err == nil {
			t.Fatal("truncated payload should not parse")
		}
	}
}

func TestSplitRejectsBadSize(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x00},
		{0x00, 0x00}, // size 0
	}
	for _, raw := range cases {
		if _, _, err := splitHeaderPayload(raw); err == nil {
			t.Errorf("splitHeaderPayload(% x) should return an error", raw)
		}
	}

	// Size larger than the record.
	if _, _, err := splitHeaderPayload([]byte{0xFF, 0xFF}); err == nil {
		t.Fatal("size 65535 with a 2-byte record should error")
	}
}

func TestSplitRejectsWrongHeaderKind(t *testing.T) {
	// Take a valid record and corrupt the Target kind byte (0 -> 7).
	raw := padRecord(t, recordF5, 64)
	raw[2] = 7
	if _, _, err := splitHeaderPayload(raw); err == nil {
		t.Fatal("corrupted header kind should be rejected")
	}
}
