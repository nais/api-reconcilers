package audit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	audit "github.com/nais/api-reconcilers/internal/reconcilers/google/audit"
)

func TestLoggkamelRequiresOnPremPostgresLogging(t *testing.T) {
	tests := []struct {
		name         string
		responseBody string
		statusCode   int
		wantResult   bool
		wantErr      bool
	}{
		{name: "active team returns true", responseBody: "true", statusCode: http.StatusOK, wantResult: true},
		{name: "inactive team returns false", responseBody: "false", statusCode: http.StatusOK, wantResult: false},
		{name: "non-200 returns error", responseBody: "", statusCode: http.StatusInternalServerError, wantErr: true},
		{name: "invalid body returns error", responseBody: "not-a-bool", statusCode: http.StatusOK, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.responseBody))
			}))
			defer srv.Close()

			client := audit.NewLoggkamelClientForTesting(srv.URL)
			got, err := client.RequiresOnPremPostgresLogging(context.Background(), "my-team")

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantResult {
				t.Errorf("RequiresOnPremPostgresLogging() = %v, want %v", got, tt.wantResult)
			}
			if want := "/api/v1/naisteam/active/my-team"; gotPath != want {
				t.Errorf("called path = %q, want %q", gotPath, want)
			}
		})
	}
}
