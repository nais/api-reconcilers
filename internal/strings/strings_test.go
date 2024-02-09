package strings_test

import (
	"testing"

	"github.com/nais/api-reconcilers/internal/strings"
	"k8s.io/utils/ptr"
)

func TestStringWithFallback(t *testing.T) {
	t.Run("Fallback not used", func(t *testing.T) {
		actual := strings.WithFallback(ptr.To("some value"), "some fallback value")
		if expected := "some value"; actual != expected {
			t.Errorf("Expected %q, got %q", expected, actual)
		}
	})

	t.Run("Fallback used", func(t *testing.T) {
		actual := strings.WithFallback(ptr.To(""), "some fallback value")
		if expected := "some fallback value"; actual != expected {
			t.Errorf("Expected %q, got %q", expected, actual)
		}
	})
}

func TestTruncate(t *testing.T) {
	t.Run("Empty string", func(t *testing.T) {
		if actual := strings.Truncate("", 5); actual != "" {
			t.Errorf("Expected empty string, got %q", actual)
		}
	})

	t.Run("String shorter than truncate length", func(t *testing.T) {
		actual := strings.Truncate("some string", 20)
		if expected := "some string"; actual != expected {
			t.Errorf("Expected %q, got %q", expected, actual)
		}
	})

	t.Run("String longer than truncate length", func(t *testing.T) {
		actual := strings.Truncate("some string", 5)
		if expected := "some "; actual != expected {
			t.Errorf("Expected %q, got %q", expected, actual)
		}
	})
}
