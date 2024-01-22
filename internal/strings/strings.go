package strings

func WithFallback(strp *string, fallback string) string {
	if strp == nil || *strp == "" {
		return fallback
	}
	return *strp
}

// Truncate will truncate the string s to the given length
func Truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length]
}
