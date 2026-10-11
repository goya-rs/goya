package ayalog

import (
	"encoding/binary"
	"fmt"
)

// minHeaderSegments is the number of TLV segments a valid aya-log header
// must contain: target, level, module, file, line, num_args.
const minHeaderSegments = 6

func ParseHeader(header []byte) (*Header, error) {
	result := parseHeaderSegments(header)
	if len(result) < minHeaderSegments {
		return nil, fmt.Errorf("malformed header: expected at least %d segments, got %d", minHeaderSegments, len(result))
	}
	if len(result[1]) < 1 {
		return nil, fmt.Errorf("malformed header: level segment is empty")
	}
	if len(result[4]) < 4 {
		return nil, fmt.Errorf("malformed header: line segment must be 4 bytes, got %d", len(result[4]))
	}
	if len(result[5]) < 4 {
		return nil, fmt.Errorf("malformed header: num_args segment must be 4 bytes, got %d", len(result[5]))
	}

	h := &Header{
		Target:  string(result[0]),
		Level:   LogLevel(result[1][0]),
		Module:  string(result[2]),
		File:    string(result[3]),
		Line:    binary.LittleEndian.Uint32(result[4]),
		NumArgs: binary.LittleEndian.Uint32(result[5]),
	}

	return h, nil
}

// parseHeaderSegments splits a TLV-encoded header into its data segments.
// It tolerates truncated trailing segments (they are simply omitted).
func parseHeaderSegments(header []byte) [][]byte {
	var result [][]byte

	for i := 1; i < len(header); {
		switch {
		case header[i] == 0x00:
			i++

		case i+1 < len(header) && header[i+1] == 0x00 && header[i] > 0x00:
			size := int(header[i])
			start := i + 2
			if start+size > len(header) {
				// Truncated segment: stop parsing.
				return result
			}
			data := header[start : start+size]
			i = start + size
			result = append(result, data)

		default:
			i++
		}
	}

	return result
}

func splitHeaderPayload(raw []byte) (header, payload []byte, err error) {
	headerSize, err := retrieveHeaderSize(raw)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) < headerSize {
		return nil, nil, fmt.Errorf("buffer too small: %d bytes", len(raw))
	}

	header = raw[:headerSize]
	payload = raw[headerSize:]
	return header, payload, nil
}

func retrieveHeaderSize(raw []byte) (int, error) {
	for i := 0; i+13 <= len(raw); i++ {
		// pattern: 04 04 00 ??
		if raw[i] == 0x04 && raw[i+1] == 0x04 && raw[i+2] == 0x00 {
			payloadLen := int(binary.LittleEndian.Uint32(raw[i+3 : i+7]))
			headerSize := i + 13

			if headerSize+payloadLen > len(raw) {
				return 0, fmt.Errorf("invalid payload length %d", payloadLen)
			}

			return headerSize, nil
		}
	}

	return 0, fmt.Errorf("payload length marker not found")
}
