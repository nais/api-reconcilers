package audit

import (
	"crypto/sha256"
	"fmt"
	"regexp"
)

// GenerateLogBucketName generates a unique bucket name with hash collision resistance. Creates one bucket per team environment (not per SQL instance).
func GenerateLogBucketName(teamSlug, envName string) string {
	naturalName := fmt.Sprintf("%s-%s", teamSlug, envName)

	if len(naturalName) <= 100 {
		return naturalName
	}

	fullIdentifier := fmt.Sprintf("%s/%s", teamSlug, envName)
	hash := sha256.Sum256([]byte(fullIdentifier))
	hashSuffix := fmt.Sprintf("%x", hash)[:8]

	availableForComponents := 100 - 8 - 1 // 1 for separator
	maxComponentLen := availableForComponents / 2

	shortTeam := truncateToLength(teamSlug, maxComponentLen)
	shortEnv := truncateToLength(envName, maxComponentLen)

	return fmt.Sprintf("%s-%s-%s", shortTeam, shortEnv, hashSuffix)
}

// truncateToLength truncates a string to the specified maximum length.
func truncateToLength(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	if maxLen <= 0 {
		return ""
	}

	if maxLen <= 3 {
		return s[:maxLen]
	}

	return s[:maxLen]
}

// GenerateLogSinkName generates a unique sink name with hash collision resistance. Creates one sink per team environment (not per SQL instance).
func GenerateLogSinkName(teamSlug, envName string) string {
	naturalName := fmt.Sprintf("sql-audit-sink-%s-%s", teamSlug, envName)

	if len(naturalName) <= 100 {
		return naturalName
	}

	fullIdentifier := fmt.Sprintf("%s/%s", teamSlug, envName)
	hash := sha256.Sum256([]byte(fullIdentifier))
	hashSuffix := fmt.Sprintf("%x", hash)[:8]

	availableForComponents := 100 - 15 - 8 - 2 // 15 for "sql-audit-sink-", 8 for hash, 2 for separators
	maxComponentLen := availableForComponents / 2

	shortTeam := truncateToLength(teamSlug, maxComponentLen)
	shortEnv := truncateToLength(envName, maxComponentLen)

	return fmt.Sprintf("sql-audit-sink-%s-%s-%s", shortTeam, shortEnv, hashSuffix)
}

// ValidateLogBucketName validates a log bucket name against Google Cloud naming rules.
func ValidateLogBucketName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("bucket name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("bucket name exceeds 100 character limit (got %d characters)", len(name))
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9]`).MatchString(name) {
		return fmt.Errorf("bucket name must start with an alphanumeric character")
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(name) {
		return fmt.Errorf("bucket name can only contain letters, digits, underscores, hyphens, and periods")
	}

	return nil
}

// ValidateLogSinkName validates a log sink name against Google Cloud naming rules.
func ValidateLogSinkName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("sink name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("sink name exceeds 100 character limit (got %d characters)", len(name))
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9]`).MatchString(name) {
		return fmt.Errorf("sink name must start with an alphanumeric character")
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(name) {
		return fmt.Errorf("sink name can only contain letters, digits, underscores, hyphens, and periods")
	}

	return nil
}
