package ayalog

import "fmt"

// ParsePayload decodes an aya-log record payload (the fields following the
// six header fields) into an ordered list of PayloadElem.
//
// The payload is a sequence of <kind u8><len u16 LE><data> fields. Text is a
// Str field; each formatted argument is optionally preceded by a DisplayHint
// field (kind 0), which is attached to the following field.
func ParsePayload(payload []byte) ([]PayloadElem, error) {
	var result []PayloadElem
	var pendingHint byte

	i := 0
	for i < len(payload) {
		f, err := readField(payload, i)
		if err != nil {
			return nil, err
		}

		switch {
		case f.kind == kindDisplayHint && len(f.data) == 0:
			// A zero-length field is padding, not a hint: skip it.
			pendingHint = 0

		case f.kind == kindDisplayHint:
			if len(f.data) < 1 {
				return nil, fmt.Errorf("malformed payload: empty display hint at offset %d", i)
			}
			pendingHint = f.data[0]

		case f.kind == kindStr:
			result = append(result, PayloadElem{Kind: kindStr, Data: f.data})
			pendingHint = 0

		default:
			result = append(result, PayloadElem{Kind: f.kind, Hint: pendingHint, Data: f.data})
			pendingHint = 0
		}

		i = f.next
	}

	return result, nil
}
