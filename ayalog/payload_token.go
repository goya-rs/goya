package ayalog

// PayloadElem is a single decoded aya-log payload field.
//
// Kind is the argument kind (see field.go). Hint is the display hint that
// preceded the field (0 when absent); the real encoder always emits a hint
// field before a formatted argument. Data holds the raw value bytes
// (little-endian for integers and floats).
type PayloadElem struct {
	Kind uint8
	Hint byte
	Data []byte
}
