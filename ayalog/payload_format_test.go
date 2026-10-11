package ayalog

import (
	"testing"
)

func TestFormatPayloadText(t *testing.T) {
	elems := []PayloadElem{{"text": []byte("hello world")}}
	got := FormatPayload(elems)
	if got != "hello world" {
		t.Errorf("FormatPayload = %q, want %q", got, "hello world")
	}
}

func TestFormatPayloadIPv4(t *testing.T) {
	elems := []PayloadElem{{"ip": []byte{192, 168, 1, 10}}}
	got := FormatPayload(elems)
	if got != "192.168.1.10" {
		t.Errorf("FormatPayload = %q, want %q", got, "192.168.1.10")
	}
}

func TestFormatPayloadMac(t *testing.T) {
	elems := []PayloadElem{{"mac": []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}}}
	got := FormatPayload(elems)
	if got != "de:ad:be:ef:00:01" {
		t.Errorf("FormatPayload = %q, want %q", got, "de:ad:be:ef:00:01")
	}
}

func TestFormatPayloadU32Values(t *testing.T) {
	u32 := make([]byte, 4)
	// 0x0102 = 258 little-endian
	u32[0] = 0x02
	u32[1] = 0x01
	cases := []struct {
		key  string
		want string
	}{
		{"default", "258"},
		{"hex", "102"},
		{"hex_u", "102"},
		{"ptr", "0x102"},
	}
	for _, c := range cases {
		elems := []PayloadElem{{c.key: u32}}
		got := FormatPayload(elems)
		if got != c.want {
			t.Errorf("FormatPayload(%s) = %q, want %q", c.key, got, c.want)
		}
	}
}

// TestFormatPayloadShortMacroNoPanic ensures a macro value shorter than 4
// bytes does not panic (B3): it falls back to a hex dump.
func TestFormatPayloadShortMacroNoPanic(t *testing.T) {
	elems := []PayloadElem{
		{"hex": {0x12}},
		{"default": {0x12, 0x34}},
		{"ptr": {}},
	}
	// Must not panic.
	_ = FormatPayload(elems)
}

func TestFormatPayloadMultipleTextSegments(t *testing.T) {
	elems := []PayloadElem{
		{"text": []byte("a")},
		{"text": []byte("b")},
	}
	got := FormatPayload(elems)
	// Two separate elems keep their order; result is the concatenation.
	if got != "ab" {
		t.Errorf("FormatPayload = %q, want %q", got, "ab")
	}
}

func TestFormatPayloadUnknownKeyHexDump(t *testing.T) {
	elems := []PayloadElem{{"unknown": {0xab, 0xcd}}}
	got := FormatPayload(elems)
	if got != "ab cd" {
		t.Errorf("FormatPayload = %q, want %q", got, "ab cd")
	}
}
