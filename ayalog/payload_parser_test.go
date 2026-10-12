package ayalog

import (
	"encoding/hex"
	"testing"
)

func TestParsePayloadFields(t *testing.T) {
	// text "hello " | hint LowerHex | U32 0x1234 | Pointer | text "world"
	payload, err := hex.DecodeString(
		"14060068656c6c6f20" + "00010002" + "08040034120000" +
			"150800efbeadde00000000" + "140500776f726c64",
	)
	if err != nil {
		t.Fatal(err)
	}

	elems, err := ParsePayload(payload)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if len(elems) != 4 {
		t.Fatalf("got %d elems, want 4", len(elems))
	}

	if elems[0].Kind != kindStr || string(elems[0].Data) != "hello " {
		t.Errorf("elem 0 = %+v, want text 'hello '", elems[0])
	}
	if elems[1].Kind != kindU32 || elems[1].Hint != hintLowerHex {
		t.Errorf("elem 1 = %+v, want U32 with LowerHex hint", elems[1])
	}
	if elems[2].Kind != kindPointer || elems[2].Hint != 0 {
		t.Errorf("elem 2 = %+v, want Pointer without hint", elems[2])
	}
	if elems[3].Kind != kindStr || string(elems[3].Data) != "world" {
		t.Errorf("elem 3 = %+v, want text 'world'", elems[3])
	}
}

func TestParsePayloadPaddingTolerated(t *testing.T) {
	// A zero-length field (kind 0, len 0) is padding: it must be skipped.
	payload, _ := hex.DecodeString("000000" + "140300616263")
	elems, err := ParsePayload(payload)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if len(elems) != 1 || string(elems[0].Data) != "abc" {
		t.Errorf("got %+v, want one text elem 'abc'", elems)
	}
}

func TestParsePayloadTruncated(t *testing.T) {
	cases := []string{
		"14",         // kind only
		"1402",       // kind + partial len
		"14040061",   // len 4 but 1 data byte
		"0001",       // hint kind with no data
		"0001000214", // hint then text kind with no len/data
	}
	for _, hexPayload := range cases {
		raw, _ := hex.DecodeString(hexPayload)
		if _, err := ParsePayload(raw); err == nil {
			t.Errorf("ParsePayload(%s) should error", hexPayload)
		}
	}
}

func TestParsePayloadEmpty(t *testing.T) {
	elems, err := ParsePayload(nil)
	if err != nil {
		t.Fatalf("ParsePayload(nil): %v", err)
	}
	if len(elems) != 0 {
		t.Errorf("got %d elems, want 0", len(elems))
	}
}
