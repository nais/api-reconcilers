package strings_test

import (
	"testing"

	"github.com/nais/api-reconcilers/internal/strings"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"
)

func TestStringWithFallback(t *testing.T) {
	t.Run("Fallback not used", func(t *testing.T) {
		assert.Equal(t, "some value", strings.WithFallback(ptr.To("some value"), "some fallback value"))
	})

	t.Run("Fallback used", func(t *testing.T) {
		assert.Equal(t, "some fallback value", strings.WithFallback(ptr.To(""), "some fallback value"))
	})
}

func TestTruncate(t *testing.T) {
	t.Run("Empty string", func(t *testing.T) {
		assert.Equal(t, "", strings.Truncate("", 5))
	})

	t.Run("String shorter than truncate length", func(t *testing.T) {
		assert.Equal(t, "some string", strings.Truncate("some string", 20))
	})

	t.Run("String longer than truncate length", func(t *testing.T) {
		assert.Equal(t, "some ", strings.Truncate("some string", 5))
	})
}
