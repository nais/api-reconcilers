package strings

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

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

func SlugHashPrefixTruncate(teamSlug, prefix string, maxLength int) string {
	hasher := sha256.New()
	hasher.Write([]byte(teamSlug))

	prefixLength := len(prefix)
	hashLength := 4
	slugLength := maxLength - prefixLength - hashLength - 2 // 2 becasue we join parts with '-'

	parts := []string{
		prefix,
		strings.TrimSuffix(Truncate(teamSlug, slugLength), "-"),
		Truncate(hex.EncodeToString(hasher.Sum(nil)), hashLength),
	}

	return strings.Join(parts, "-")
}
