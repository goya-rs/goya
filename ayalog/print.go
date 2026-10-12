package ayalog

import "fmt"

// formatLogLine renders one aya-log record as a line, e.g.
//
//	[INFO  demo::main] hello world
func formatLogLine(head *Header, msg string) string {
	progFile := filenameWithoutExt(head.File)

	if progFile == "main" {
		return fmt.Sprintf("[%s  %s] %s", head.Level.String(), head.Target, msg)
	}

	return fmt.Sprintf("[%s  %s::%s] %s", head.Level.String(), head.Target, progFile, msg)
}
