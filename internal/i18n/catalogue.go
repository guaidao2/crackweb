package i18n

import "fmt"

// sprintf is fmt.Sprintf behind a seam, so T's formatting behaviour is easy to
// exercise in tests.
func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

// catalogues maps every supported language to its message table.
var catalogues = map[Lang]map[Key]string{
	EN: english,
	ZH: chinese,
}
