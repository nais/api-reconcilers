package google_gcp_reconciler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nais/api/pkg/apiclient/protoapi"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/option"
)

func TestGetOrCreateProject(t *testing.T) {
	ctx := context.Background()
	env := &protoapi.TeamEnvironment{EnvironmentName: "dev-gcp"}
	team := &protoapi.Team{Slug: "team-a"}

	t.Run("adopt existing project on 409 when labels match team", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/v3/projects":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":{"code":409,"message":"already exists"}}`))
			case r.Method == http.MethodGet && r.URL.Path == "/v3/projects:search":
				if got := r.URL.Query().Get("query"); got != "id:team-a-dev-0000" {
					t.Fatalf("unexpected search query: %q", got)
				}
				_ = json.NewEncoder(w).Encode(&cloudresourcemanager.SearchProjectsResponse{
					Projects: []*cloudresourcemanager.Project{{
						ProjectId: "team-a-dev-0000",
						Labels: map[string]string{
							ManagedByLabelName: ManagedByLabelValue,
							"team":             "team-a",
						},
					}},
				})
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		}))
		defer server.Close()

		crm, err := cloudresourcemanager.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(server.URL))
		if err != nil {
			t.Fatalf("new cloudresourcemanager service: %v", err)
		}

		r := &googleGcpReconciler{
			gcpServices: &GcpServices{CloudResourceManagerProjectsService: crm.Projects},
		}

		project, err := r.getOrCreateProject(ctx, "team-a-dev-0000", env, 123, team)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if got := project.ProjectId; got != "team-a-dev-0000" {
			t.Fatalf("unexpected project id: %q", got)
		}
	})

	t.Run("reject adoption on 409 when labels do not match team", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/v3/projects":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":{"code":409,"message":"already exists"}}`))
			case r.Method == http.MethodGet && r.URL.Path == "/v3/projects:search":
				_ = json.NewEncoder(w).Encode(&cloudresourcemanager.SearchProjectsResponse{
					Projects: []*cloudresourcemanager.Project{{
						ProjectId: "team-a-dev-0000",
						Labels: map[string]string{
							ManagedByLabelName: ManagedByLabelValue,
							"team":             "team-b",
						},
					}},
				})
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		}))
		defer server.Close()

		crm, err := cloudresourcemanager.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(server.URL))
		if err != nil {
			t.Fatalf("new cloudresourcemanager service: %v", err)
		}

		r := &googleGcpReconciler{
			gcpServices: &GcpServices{CloudResourceManagerProjectsService: crm.Projects},
		}

		_, err = r.getOrCreateProject(ctx, "team-a-dev-0000", env, 123, team)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}

		if !strings.Contains(err.Error(), "refusing to adopt existing GCP project after 409") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
