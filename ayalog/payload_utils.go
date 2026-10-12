package ayalog

import (
	"fmt"
	"strings"
)

func hexDump(b []byte) string {
	var sb strings.Builder
	for i, v := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(fmt.Sprintf("%02x", v))
	}
	return sb.String()
}

func formatMAC(b []byte) string {
	if len(b) != 6 {
		return fmt.Sprintf("invalid mac (%d bytes)", len(b))
	}

	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = fmt.Sprintf("%02x", b[i])
	}

	return strings.Join(parts, ":")
}
