package ayalog

import (
	"testing"
)

func TestFormatText(t *testing.T) {
	elems := []PayloadElem{{Kind: kindStr, Data: []byte("hello world")}}
	if got := FormatPayload(elems); got != "hello world" {
		t.Errorf("FormatPayload = %q, want %q", got, "hello world")
	}
}

func TestFormatIPv4Hints(t *testing.T) {
	// Both a raw IPv4 field and the :i hint on an integer render as dotted.
	elems := []PayloadElem{
		{Kind: kindIPv4, Data: []byte{192, 168, 1, 10}},
		{Kind: kindU32, Hint: hintIP, Data: []byte{10, 1, 2, 3}},
		{Kind: kindArrU8Len4, Data: []byte{8, 8, 8, 8}},
	}
	if got := FormatPayload(elems); got != "192.168.1.1010.1.2.38.8.8.8" {
		t.Errorf("FormatPayload = %q", got)
	}
}

func TestFormatIPv6Hints(t *testing.T) {
	v6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0x00, 0, 0x42}
	elems := []PayloadElem{
		{Kind: kindIPv6, Data: v6},
		{Kind: kindArrU8Len16, Data: v6},
		// [u16; 8] big-endian halves
		{Kind: kindArrU16Len8, Data: []byte{0x01, 0x20, 0xb8, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0xff, 0x42, 0x00}},
	}
	want := "2001:db8::ff00:42"
	for i, e := range elems {
		if got := FormatPayload([]PayloadElem{e}); got != want {
			t.Errorf("case %d: FormatPayload = %q, want %q", i, got, want)
		}
	}
}

func TestFormatMAC(t *testing.T) {
	elems := []PayloadElem{
		{Kind: kindArrU8Len6, Data: []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}},
		{Kind: kindArrU8Len6, Hint: hintLowerMAC, Data: []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}},
		{Kind: kindArrU8Len6, Hint: hintUpperMAC, Data: []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}},
	}
	if got := FormatPayload(elems); got != "de:ad:be:ef:00:01de:ad:be:ef:00:01DE:AD:BE:EF:00:01" {
		t.Errorf("FormatPayload = %q", got)
	}
}

func TestFormatIntegersByKind(t *testing.T) {
	// Signedness matters: -42i32 must not print as 4294967254.
	u32 := []byte{0xd6, 0xff, 0xff, 0xff}
	cases := []struct {
		elem PayloadElem
		want string
	}{
		{PayloadElem{Kind: kindI32, Data: u32}, "-42"},
		{PayloadElem{Kind: kindU32, Data: u32}, "4294967254"},
		{PayloadElem{Kind: kindI8, Data: []byte{0x7f}}, "127"},
		{PayloadElem{Kind: kindI8, Data: []byte{0x80}}, "-128"},
		{PayloadElem{Kind: kindU8, Data: []byte{200}}, "200"},
		{PayloadElem{Kind: kindU64, Data: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}, "18446744073709551615"},
		{PayloadElem{Kind: kindI64, Data: []byte{0xd6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}, "-42"},
	}
	for _, c := range cases {
		if got := FormatPayload([]PayloadElem{c.elem}); got != c.want {
			t.Errorf("kind %d: FormatPayload = %q, want %q", c.elem.Kind, got, c.want)
		}
	}
}

func TestFormatFloats(t *testing.T) {
	cases := []struct {
		elem PayloadElem
		want string
	}{
		{PayloadElem{Kind: kindF32, Data: []byte{0x00, 0x00, 0x00, 0x40}}, "2"},
		{PayloadElem{Kind: kindF64, Data: []byte{0x1f, 0x85, 0xeb, 0x51, 0xb8, 0x1e, 0x09, 0x40}}, "3.14"},
	}
	for _, c := range cases {
		if got := FormatPayload([]PayloadElem{c.elem}); got != c.want {
			t.Errorf("kind %d: FormatPayload = %q, want %q", c.elem.Kind, got, c.want)
		}
	}
}

func TestFormatHexHints(t *testing.T) {
	abc := []byte{0xcd, 0xab, 0x00, 0x00} // 0xabcd
	if got := FormatPayload([]PayloadElem{{Kind: kindU32, Hint: hintLowerHex, Data: abc}}); got != "abcd" {
		t.Errorf("lower hex = %q, want abcd", got)
	}
	if got := FormatPayload([]PayloadElem{{Kind: kindU32, Hint: hintUpperHex, Data: abc}}); got != "ABCD" {
		t.Errorf("upper hex = %q, want ABCD", got)
	}
}

func TestFormatPointer(t *testing.T) {
	ptr := []byte{0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00}
	elems := []PayloadElem{
		{Kind: kindPointer, Data: ptr},
		{Kind: kindU64, Hint: hintPointer, Data: ptr},
	}
	for i, e := range elems {
		if got := FormatPayload([]PayloadElem{e}); got != "0xdeadbeef" {
			t.Errorf("case %d: FormatPayload = %q, want 0xdeadbeef", i, got)
		}
	}
}

func TestFormatBytesAndUnknownKind(t *testing.T) {
	cases := []struct {
		elem PayloadElem
		want string
	}{
		{PayloadElem{Kind: kindBytes, Data: []byte{0xab, 0xcd}}, "ab cd"},
		{PayloadElem{Kind: 0xfe, Data: []byte{0x01, 0x02}}, "01 02"},
	}
	for _, c := range cases {
		if got := FormatPayload([]PayloadElem{c.elem}); got != c.want {
			t.Errorf("FormatPayload = %q, want %q", got, c.want)
		}
	}
}

// TestFormatUndersizedValuesNoPanic ensures values shorter than their
// nominal size fall back to a hex dump (or zero) instead of panicking.
func TestFormatUndersizedValuesNoPanic(t *testing.T) {
	elems := []PayloadElem{
		{Kind: kindU32, Data: []byte{0x12}},
		{Kind: kindI64, Data: []byte{0x12, 0x34}},
		{Kind: kindU8, Data: nil},
		{Kind: kindF64, Data: []byte{0x01}},
		{Kind: kindIPv4, Data: []byte{1, 2, 3}},
	}
	_ = FormatPayload(elems) // must not panic
}

func TestFormatEmpty(t *testing.T) {
	if got := FormatPayload(nil); got != "" {
		t.Errorf("FormatPayload(nil) = %q, want empty", got)
	}
}
