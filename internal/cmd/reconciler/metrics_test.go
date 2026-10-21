package reconciler

import (
	"testing"

	"go.opentelemetry.io/otel/sdk/resource"
)

func TestNewResourceSchemaMatchesSDK(t *testing.T) {
	res, err := newResource()
	if err != nil {
		t.Fatalf("newResource(): %v; check that the semconv import in metrics.go matches the SDK schema %q", err, resource.Default().SchemaURL())
	}
	if got, want := res.SchemaURL(), resource.Default().SchemaURL(); got != want {
		t.Errorf("resource schema = %q, want SDK schema %q; update the semconv import in metrics.go", got, want)
	}
}
