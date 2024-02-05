package nais_deploy_reconciler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	nais_deploy_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/nais/deploy"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
)

func TestNaisDeployReconciler_Reconcile(t *testing.T) {
	ctx := context.Background()

	const (
		teamSlug     = "team"
		provisionKey = "736563726574"
	)

	naisTeam := &protoapi.Team{Slug: teamSlug}

	log, _ := test.NewNullLogger()

	t.Run("invalid key", func(t *testing.T) {
		url, key := "http://localhost", "invalid key"
		if _, err := nais_deploy_reconciler.New(url, key); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("key successfully provisioned", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestData := &nais_deploy_reconciler.ProvisionApiKeyRequest{}
			if err := json.NewDecoder(r.Body).Decode(requestData); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(r.Header.Get("x-nais-signature")) != 64 {
				t.Errorf("incorrect length of x-nais-signature header")
			}

			if requestData.Team != teamSlug {
				t.Errorf("incorrect team slug in request data")
			}

			if requestData.Rotate != false {
				t.Errorf("incorrect rotate value in request data")
			}

			w.WriteHeader(http.StatusCreated)
		}))
		defer srv.Close()

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "nais:deploy:provision-deploy-key"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		reconciler, err := nais_deploy_reconciler.New(srv.URL, provisionKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("internal server error when provisioning key", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		apiClient, _ := apiclient.NewMockClient(t)

		reconciler, err := nais_deploy_reconciler.New(srv.URL, provisionKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "500 Internal Server Error") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("team key does not change", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		apiClient, _ := apiclient.NewMockClient(t)

		reconciler, err := nais_deploy_reconciler.New(srv.URL, provisionKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
