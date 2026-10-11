package ayalog

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// uint32Value decodes a little-endian u32 macro value, falling back to a
// hex dump for undersized values instead of panicking.
func uint32Value(v []byte) (uint32, bool) {
	if len(v) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(v), true
}

func FormatPayload(elems []PayloadElem) string {
	var b strings.Builder

	for _, elem := range elems {
		for k, v := range elem {
			switch k {
			case "text":
				b.WriteString(string(v))
			case "ip":
				if len(v) == 4 {
					fmt.Fprintf(&b, "%d.%d.%d.%d", v[0], v[1], v[2], v[3])
				} else {
					b.WriteString(formatIPv6(v))
				}
			case "mac":
				b.WriteString(formatMAC(v))
			case "mac_u":
				b.WriteString(strings.ToUpper(formatMAC(v)))
			case "hex", "hex_u", "ptr", "default":
				val, ok := uint32Value(v)
				if !ok {
					b.WriteString(hexDump(v))
					break
				}
				switch k {
				case "hex":
					fmt.Fprintf(&b, "%x", val)
				case "hex_u":
					fmt.Fprintf(&b, "%X", val)
				case "ptr":
					fmt.Fprintf(&b, "%#x", val)
				case "default":
					fmt.Fprintf(&b, "%d", val)
				}
			default:
				b.WriteString(hexDump(v))
			}
		}
	}
	return b.String()
}
