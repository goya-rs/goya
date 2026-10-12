package ayalog

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"
)

// FormatPayload renders decoded payload elements as a single string, the
// way aya-log would have printed them: text verbatim, and each value
// formatted according to its display hint (or the natural formatting of its
// kind when no hint is present).
func FormatPayload(elems []PayloadElem) string {
	var b strings.Builder

	for _, e := range elems {
		b.WriteString(formatElem(e))
	}
	return b.String()
}

func formatElem(e PayloadElem) string {
	if e.Kind == kindStr {
		return string(e.Data)
	}

	// Display hints take priority over the natural formatting of the kind.
	switch e.Hint {
	case hintLowerHex:
		return fmt.Sprintf("%x", uintValue(e.Data))
	case hintUpperHex:
		return fmt.Sprintf("%X", uintValue(e.Data))
	case hintIP:
		if len(e.Data) == 4 || len(e.Data) == 16 {
			return net.IP(e.Data).String()
		}
		return hexDump(e.Data)
	case hintLowerMAC:
		return formatMAC(e.Data)
	case hintUpperMAC:
		return strings.ToUpper(formatMAC(e.Data))
	case hintPointer:
		return fmt.Sprintf("%#x", uintValue(e.Data))
	}

	// No hint (or the default hint): render by kind.
	return formatByKind(e)
}

// formatByKind renders a value using the natural formatting of its kind.
func formatByKind(e PayloadElem) string {
	switch e.Kind {
	case kindIPv4, kindArrU8Len4:
		if len(e.Data) == 4 {
			return net.IP(e.Data).String()
		}
		return hexDump(e.Data)
	case kindIPv6, kindArrU8Len16:
		if len(e.Data) == 16 {
			return net.IP(e.Data).String()
		}
		return hexDump(e.Data)
	case kindArrU16Len8:
		if len(e.Data) == 16 {
			var ip [16]byte
			for i := 0; i < 8; i++ {
				binary.BigEndian.PutUint16(ip[i*2:], binary.LittleEndian.Uint16(e.Data[i*2:]))
			}
			return net.IP(ip[:]).String()
		}
		return hexDump(e.Data)
	case kindArrU8Len6:
		return formatMAC(e.Data)
	case kindBytes:
		return hexDump(e.Data)
	case kindPointer:
		return fmt.Sprintf("%#x", uintValue(e.Data))

	case kindI8:
		if len(e.Data) >= 1 {
			return fmt.Sprintf("%d", int8(e.Data[0]))
		}
	case kindI16:
		if len(e.Data) >= 2 {
			return fmt.Sprintf("%d", int16(binary.LittleEndian.Uint16(e.Data)))
		}
	case kindI32:
		if len(e.Data) >= 4 {
			return fmt.Sprintf("%d", int32(binary.LittleEndian.Uint32(e.Data)))
		}
	case kindI64, kindIsize:
		if len(e.Data) >= 8 {
			return fmt.Sprintf("%d", int64(binary.LittleEndian.Uint64(e.Data)))
		}
	case kindU8:
		if len(e.Data) >= 1 {
			return fmt.Sprintf("%d", e.Data[0])
		}
	case kindU16:
		if len(e.Data) >= 2 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint16(e.Data))
		}
	case kindU32:
		if len(e.Data) >= 4 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint32(e.Data))
		}
	case kindU64, kindUsize:
		if len(e.Data) >= 8 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint64(e.Data))
		}
	case kindF32:
		if len(e.Data) >= 4 {
			return fmt.Sprintf("%g", math.Float32frombits(binary.LittleEndian.Uint32(e.Data)))
		}
	case kindF64:
		if len(e.Data) >= 8 {
			return fmt.Sprintf("%g", math.Float64frombits(binary.LittleEndian.Uint64(e.Data)))
		}
	}

	// Unknown kind: hex dump, never panic.
	return hexDump(e.Data)
}

// uintValue decodes a little-endian unsigned integer of any size (1..8
// bytes). Undersized values decode as zero rather than panicking.
func uintValue(v []byte) uint64 {
	var buf [8]byte
	copy(buf[:], v)
	return binary.LittleEndian.Uint64(buf[:])
}
