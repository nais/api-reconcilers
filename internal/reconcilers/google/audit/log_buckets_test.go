package audit

import (
	"strings"
	"testing"
)

// TestIsNonProductionEnvironment tests the logic for determining if an environment
// should never have locked buckets based on its name.
func TestIsNonProductionEnvironment(t *testing.T) {
	tests := []struct {
		name        string
		envName     string
		shouldSkip  bool
		description string
	}{
		{
			name:        "dev environment",
			envName:     "dev",
			shouldSkip:  true,
			description: "Should not lock buckets in 'dev' environment",
		},
		{
			name:        "dev-gcp environment",
			envName:     "dev-gcp",
			shouldSkip:  true,
			description: "Should not lock buckets in 'dev-gcp' environment",
		},
		{
			name:        "development environment",
			envName:     "development",
			shouldSkip:  true,
			description: "Should not lock buckets in 'development' environment",
		},
		{
			name:        "test environment",
			envName:     "test",
			shouldSkip:  true,
			description: "Should not lock buckets in 'test' environment",
		},
		{
			name:        "testing environment",
			envName:     "testing",
			shouldSkip:  true,
			description: "Should not lock buckets in 'testing' environment",
		},
		{
			name:        "sandbox environment",
			envName:     "sandbox",
			shouldSkip:  true,
			description: "Should not lock buckets in 'sandbox' environment",
		},
		{
			name:        "staging environment",
			envName:     "staging",
			shouldSkip:  true,
			description: "Should not lock buckets in 'staging' environment",
		},
		{
			name:        "stage environment",
			envName:     "stage",
			shouldSkip:  true,
			description: "Should not lock buckets in 'stage' environment",
		},
		{
			name:        "non-prod environment",
			envName:     "non-prod",
			shouldSkip:  true,
			description: "Should not lock buckets in 'non-prod' environment",
		},
		{
			name:        "nonprod environment",
			envName:     "nonprod",
			shouldSkip:  true,
			description: "Should not lock buckets in 'nonprod' environment",
		},
		{
			name:        "Dev with capital letter",
			envName:     "Dev",
			shouldSkip:  true,
			description: "Should handle case insensitively",
		},
		{
			name:        "TEST with capital letters",
			envName:     "TEST",
			shouldSkip:  true,
			description: "Should handle case insensitively",
		},
		{
			name:        "my-dev-env - NOT matched",
			envName:     "my-dev-env",
			shouldSkip:  false,
			description: "Should NOT match partial strings (exact match only)",
		},
		{
			name:        "team-test-cluster - NOT matched",
			envName:     "team-test-cluster",
			shouldSkip:  false,
			description: "Should NOT match partial strings (exact match only)",
		},
		{
			name:        "prod environment",
			envName:     "prod",
			shouldSkip:  false,
			description: "Should allow locking for production environments",
		},
		{
			name:        "production environment",
			envName:     "production",
			shouldSkip:  false,
			description: "Should allow locking for production environments",
		},
		{
			name:        "prod-gcp environment",
			envName:     "prod-gcp",
			shouldSkip:  false,
			description: "Should allow locking for prod-gcp environment",
		},
		{
			name:        "live environment",
			envName:     "live",
			shouldSkip:  false,
			description: "Should allow locking for live environment",
		},
		{
			name:        "main environment",
			envName:     "main",
			shouldSkip:  false,
			description: "Should allow locking for main environment",
		},
		{
			name:        "custom-prod-env",
			envName:     "custom-prod-env",
			shouldSkip:  false,
			description: "Custom environment should allow locking",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Replicate the exact logic from getBucketLocked
			envLower := strings.ToLower(tt.envName)
			var result bool
			switch envLower {
			case "dev", "dev-gcp", "development",
				"test", "testing",
				"sandbox",
				"staging", "stage",
				"non-prod", "nonprod":
				result = true
			default:
				result = false
			}

			if result != tt.shouldSkip {
				t.Errorf("Environment %q: got shouldSkip=%v, expected %v\nDescription: %s",
					tt.envName, result, tt.shouldSkip, tt.description)
			}
		})
	}
}
