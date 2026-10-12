package ayalog

import (
	"encoding/binary"
	"fmt"
)

var headerKinds = []uint8{
	fieldTarget, fieldLevel, fieldModule, fieldFile, fieldLine, fieldNumArgs,
}

// ParseHeader decodes the header of an aya-log record into a Header.
//
// header is the leading part of a raw record as returned by
// splitHeaderPayload: the u16 LE record size followed by the six header
// fields (target, level, module, file, line, num_args), in that order.
// Malformed input returns an error, never a panic.
func ParseHeader(header []byte) (*Header, error) {
	h := &Header{}

	if len(header) < 2 {
		return nil, fmt.Errorf("malformed header: %d bytes", len(header))
	}

	i := 2 // skip the record size field
	for _, wantKind := range headerKinds {
		if i >= len(header) {
			return nil, fmt.Errorf("malformed header: missing field %d", wantKind)
		}
		f, err := readField(header, i)
		if err != nil {
			return nil, fmt.Errorf("malformed header: %w", err)
		}
		if f.kind != wantKind {
			return nil, fmt.Errorf("malformed header: unexpected field kind %d at offset %d, want %d", f.kind, i, wantKind)
		}
		switch wantKind {
		case fieldTarget:
			h.Target = string(f.data)
		case fieldLevel:
			if len(f.data) < 1 {
				return nil, fmt.Errorf("malformed header: empty level field")
			}
			h.Level = LogLevel(f.data[0])
		case fieldModule:
			h.Module = string(f.data)
		case fieldFile:
			h.File = string(f.data)
		case fieldLine:
			if len(f.data) < 4 {
				return nil, fmt.Errorf("malformed header: line field is %d bytes, want 4", len(f.data))
			}
			h.Line = binary.LittleEndian.Uint32(f.data)
		case fieldNumArgs:
			if len(f.data) < 4 {
				return nil, fmt.Errorf("malformed header: num_args field is %d bytes, want 4", len(f.data))
			}
			h.NumArgs = binary.LittleEndian.Uint32(f.data)
		}
		i = f.next
	}

	return h, nil
}

// splitHeaderPayload splits a raw ring buffer record into its header and
// payload. The record starts with a u16 LE total size, followed by the six
// header fields; the payload is the remainder up to the end of the record
// (the ring buffer pads the entry with zeros up to a power-of-two capacity,
// which are ignored).
func splitHeaderPayload(raw []byte) (header, payload []byte, err error) {
	if len(raw) < 2 {
		return nil, nil, fmt.Errorf("record too small: %d bytes", len(raw))
	}

	recordSize := int(binary.LittleEndian.Uint16(raw[:2]))
	if recordSize < 2 || recordSize > len(raw) {
		return nil, nil, fmt.Errorf("invalid record size %d (record is %d bytes)", recordSize, len(raw))
	}

	// The record may be padded up to the reserved capacity; only the first
	// recordSize bytes are meaningful.
	end := recordSize

	// Walk the six header fields to find where the payload starts.
	i := 2
	headerEnd := 0
	for _, wantKind := range headerKinds {
		if i >= end {
			return nil, nil, fmt.Errorf("malformed header: missing field %d", wantKind)
		}
		f, err := readField(raw, i)
		if err != nil {
			return nil, nil, fmt.Errorf("malformed header: %w", err)
		}
		if f.kind != wantKind {
			return nil, nil, fmt.Errorf("malformed header: unexpected field kind %d at offset %d, want %d", f.kind, i, wantKind)
		}
		i = f.next
	}
	headerEnd = i

	return raw[:headerEnd], raw[headerEnd:end], nil
}
