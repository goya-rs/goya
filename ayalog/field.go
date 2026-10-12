package ayalog

import (
	"encoding/binary"
	"fmt"
)

// field is a single aya-log record field: <kind u8><len u16 LE><data>.
type field struct {
	kind uint8
	data []byte
	next int // offset just past this field
}

// readField decodes one field at offset i of raw.
func readField(raw []byte, i int) (field, error) {
	if i+3 > len(raw) {
		return field{}, fmt.Errorf("truncated field header at offset %d", i)
	}
	kind := raw[i]
	size := int(binary.LittleEndian.Uint16(raw[i+1 : i+3]))
	start := i + 3
	if start+size > len(raw) {
		return field{}, fmt.Errorf("truncated field data at offset %d (need %d bytes)", i, size)
	}
	return field{kind: kind, data: raw[start : start+size], next: start + size}, nil
}

// Header field kinds (aya-log-common 0.2.0 RecordFieldKind). A record's
// header is exactly these six fields, in this order.
const (
	fieldTarget  uint8 = 0
	fieldLevel   uint8 = 1
	fieldModule  uint8 = 2
	fieldFile    uint8 = 3
	fieldLine    uint8 = 4
	fieldNumArgs uint8 = 5
)

// Argument field kinds (aya-log-common 0.2.0 ArgumentKind).
const (
	kindDisplayHint uint8 = 0x00
	kindI8          uint8 = 0x01
	kindI16         uint8 = 0x02
	kindI32         uint8 = 0x03
	kindI64         uint8 = 0x04
	kindIsize       uint8 = 0x05
	kindU8          uint8 = 0x06
	kindU16         uint8 = 0x07
	kindU32         uint8 = 0x08
	kindU64         uint8 = 0x09
	kindUsize       uint8 = 0x0A
	kindF32         uint8 = 0x0B
	kindF64         uint8 = 0x0C
	kindIPv4        uint8 = 0x0D
	kindIPv6        uint8 = 0x0E
	kindArrU8Len4   uint8 = 0x0F
	kindArrU8Len6   uint8 = 0x10
	kindArrU8Len16  uint8 = 0x11
	kindArrU16Len8  uint8 = 0x12
	kindBytes       uint8 = 0x13
	kindStr         uint8 = 0x14
	kindPointer     uint8 = 0x15
)

// Display hints (aya-log-common 0.2.0 DisplayHint). A hint field (kind 0,
// one data byte) immediately precedes the argument field it qualifies.
const (
	hintDefault  byte = 1
	hintLowerHex byte = 2
	hintUpperHex byte = 3
	hintIP       byte = 4
	hintLowerMAC byte = 5
	hintUpperMAC byte = 6
	hintPointer  byte = 7
)
