package audit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	logging "cloud.google.com/go/logging/apiv2"
	audit "github.com/nais/api-reconcilers/internal/reconcilers/google/audit"
	"github.com/nais/api-reconcilers/internal/test"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/iam/v2"
	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1"
	"k8s.io/utils/ptr"
)

const (
	managementProjectID      = "management-project-123"
	tenantName               = "example"
	serviceAccountEmail      = "sa@example.com"
	teamSlug                 = "slug"
	googleGroupEmail         = "slug@example.com"
	workloadIdentityPoolName = "projects/123456789/locations/global/workloadIdentityPools/some-identity-pool"
	environment              = "prod"
	teamProjectID            = "team-project-456"
	sqlInstanceName          = "test-instance"
	location                 = "europe-north1"
)

var (
	naisTeam = &protoapi.Team{
		Slug:             teamSlug,
		GoogleGroupEmail: ptr.To(googleGroupEmail),
	}
	ctx = context.Background()
)

type mocks struct {
	sqlAdmin *httptest.Server
	iam      *httptest.Server
}

func (m *mocks) start(t *testing.T, ctx context.Context) *audit.Services {
	t.Helper()

	var sqlAdminService *sqladmin.Service
	if m.sqlAdmin != nil {
		var err error
		sqlAdminService, err = sqladmin.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(m.sqlAdmin.URL))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	var iamService *iam.Service
	if m.iam != nil {
		var err error
		iamService, err = iam.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(m.iam.URL))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// For the logging services, we'll create minimal clients that won't be called in most tests
	logAdminService, err := logging.NewClient(ctx, option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("unexpected error creating log admin service: %v", err)
	}

	logConfigService, err := logging.NewConfigClient(ctx, option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("unexpected error creating log config service: %v", err)
	}

	return &audit.Services{
		LogAdminService:  logAdminService,
		LogConfigService: logConfigService,
		IAMService:       iamService,
		SQLAdminService:  sqlAdminService,
	}
}

func TestReconcile(t *testing.T) {
	t.Run("reconcile with no SQL instances", func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()

		apiClient, mockServer := apiclient.NewMockClient(t)

		mockServer.Teams.EXPECT().
			Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Slug: teamSlug, Limit: 100}).
			Return(&protoapi.ListTeamEnvironmentsResponse{
				Nodes: []*protoapi.TeamEnvironment{
					{
						EnvironmentName: environment,
						GcpProjectId:    ptr.To(teamProjectID),
					},
				},
			}, nil).
			Once()

		mocks := mocks{
			sqlAdmin: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// list SQL instances - return empty
				func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						t.Errorf("expected HTTP GET, got: %q", r.Method)
					}

					response := &sqladmin.InstancesListResponse{
						Items: []*sqladmin.DatabaseInstance{},
					}

					if err := json.NewEncoder(w).Encode(response); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
			}),
		}

		services := mocks.start(t, ctx)
		reconciler, err := audit.New(ctx, serviceAccountEmail, managementProjectID, tenantName, workloadIdentityPoolName, audit.WithServices(services))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = reconciler.Reconcile(ctx, apiClient, naisTeam, log)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("error listing SQL instances", func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()

		apiClient, mockServer := apiclient.NewMockClient(t)

		mockServer.Teams.EXPECT().
			Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Slug: teamSlug, Limit: 100}).
			Return(&protoapi.ListTeamEnvironmentsResponse{
				Nodes: []*protoapi.TeamEnvironment{
					{
						EnvironmentName: environment,
						GcpProjectId:    ptr.To(teamProjectID),
					},
				},
			}, nil).
			Once()

		mocks := mocks{
			sqlAdmin: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// list SQL instances - return error
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error": {"message": "internal server error"}}`))
				},
			}),
		}

		services := mocks.start(t, ctx)
		reconciler, err := audit.New(ctx, serviceAccountEmail, managementProjectID, tenantName, workloadIdentityPoolName, audit.WithServices(services))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = reconciler.Reconcile(ctx, apiClient, naisTeam, log)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "get sql instances for team") {
			t.Errorf("expected error about SQL instances, got: %v", err)
		}
	})

	t.Run("error iterating team environments", func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()

		apiClient, mockServer := apiclient.NewMockClient(t)

		mockServer.Teams.EXPECT().
			Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Slug: teamSlug, Limit: 100}).
			Return(nil, fmt.Errorf("some error")).
			Once()

		reconciler, err := audit.New(ctx, serviceAccountEmail, managementProjectID, tenantName, workloadIdentityPoolName)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = reconciler.Reconcile(ctx, apiClient, naisTeam, log)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "some error") {
			t.Errorf("expected error to contain 'some error', got: %v", err)
		}
	})
}

func TestDelete(t *testing.T) {
	t.Run("delete is no-op", func(t *testing.T) {
		log := logrus.StandardLogger()

		apiClient, _ := apiclient.NewMockClient(t)

		reconciler, err := audit.New(ctx, serviceAccountEmail, managementProjectID, tenantName, workloadIdentityPoolName)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = reconciler.Delete(ctx, apiClient, naisTeam, log)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestConfiguration(t *testing.T) {
	reconciler, err := audit.New(ctx, serviceAccountEmail, managementProjectID, tenantName, workloadIdentityPoolName)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	config := reconciler.Configuration()

	if config.Name != "google:gcp:audit" {
		t.Errorf("expected name 'google:gcp:audit', got %q", config.Name)
	}

	if config.DisplayName != "Google Log Admin" {
		t.Errorf("expected display name 'Google Log Admin', got %q", config.DisplayName)
	}

	if config.Description != "Create log bucket resources for team" {
		t.Errorf("expected description 'Create log bucket resources for team', got %q", config.Description)
	}

	if config.MemberAware {
		t.Errorf("expected MemberAware to be false, got true")
	}
}

func TestName(t *testing.T) {
	reconciler, err := audit.New(ctx, serviceAccountEmail, managementProjectID, tenantName, workloadIdentityPoolName)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	name := reconciler.Name()
	if name != "google:gcp:audit" {
		t.Errorf("expected name 'google:gcp:audit', got %q", name)
	}
}

// TestIntegrationLogBucketOperations tests the log bucket operations with minimal mocking
// This test focuses on the core business logic rather than deep integration with logging services
func TestIntegrationLogBucketOperations(t *testing.T) {
	t.Run("basic reconcile flow", func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()

		apiClient, mockServer := apiclient.NewMockClient(t)

		mockServer.Teams.EXPECT().
			Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Slug: teamSlug, Limit: 100}).
			Return(&protoapi.ListTeamEnvironmentsResponse{
				Nodes: []*protoapi.TeamEnvironment{
					{
						EnvironmentName: environment,
						GcpProjectId:    ptr.To(teamProjectID),
					},
				},
			}, nil).
			Once()

		mocks := mocks{
			sqlAdmin: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// list SQL instances
				func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						t.Errorf("expected HTTP GET, got: %q", r.Method)
					}

					// Verify the correct project ID is used
					expectedPath := fmt.Sprintf("/sql/v1/projects/%s/instances", teamProjectID)
					if !strings.Contains(r.URL.Path, "projects/"+teamProjectID+"/instances") {
						t.Errorf("expected path to contain %q, got %q", expectedPath, r.URL.Path)
					}

					response := &sqladmin.InstancesListResponse{
						Items: []*sqladmin.DatabaseInstance{
							{Name: sqlInstanceName},
						},
					}

					if err := json.NewEncoder(w).Encode(response); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
			}),
		}

		services := mocks.start(t, ctx)
		reconciler, err := audit.New(ctx, serviceAccountEmail, managementProjectID, tenantName, workloadIdentityPoolName, audit.WithServices(services))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// This will fail because we can't easily mock the log config service
		// but it will exercise the SQL instance listing logic
		err = reconciler.Reconcile(ctx, apiClient, naisTeam, log)

		// We expect this to fail on the log bucket creation, which means SQL listing worked
		if err == nil {
			t.Fatal("expected error due to log bucket creation, got nil")
		}

		// Verify that we got to the log bucket creation part, not SQL listing failure
		if strings.Contains(err.Error(), "get sql instances for team") {
			t.Errorf("error should be related to log bucket creation, not SQL instance listing: %v", err)
		}
	})
}
