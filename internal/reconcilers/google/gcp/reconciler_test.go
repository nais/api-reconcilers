package google_gcp_reconciler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nais/api-reconcilers/internal/cmd/reconciler/config"
	"github.com/nais/api-reconcilers/internal/gcp"
	google_gcp_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/gcp"
	"github.com/nais/api-reconcilers/internal/test"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/cloudbilling/v1"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/serviceusage/v1"
	"k8s.io/utils/ptr"
)

const (
	env              = "prod"
	teamFolderID     = 123
	clusterProjectID = "some-project-123"
	tenantName       = "example"
	tenantDomain     = "example.com"
	billingAccount   = "billingAccounts/123"
	numberOfAPIs     = 14

	teamSlug         = "slug"
	googleGroupEmail = "slug@example.com"
)

var (
	clusters = gcp.Clusters{
		env: {
			TeamsFolderID: teamFolderID,
			ProjectID:     clusterProjectID,
		},
	}
	naisTeam = &protoapi.Team{
		Slug:             teamSlug,
		GoogleGroupEmail: ptr.To(googleGroupEmail),
	}
	naisTeamWithoutGoogleGroupEmail = &protoapi.Team{
		Slug: teamSlug,
	}
	ctx = context.Background()

	aliasList = map[string]string{"prodalias": env}
)

func TestReconcile(t *testing.T) {
	t.Run("fail early when unable to load reconciler state", func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Slug: teamSlug, Limit: 100}).
			Return(nil, fmt.Errorf("some error")).
			Once()

		reconcilers, err := google_gcp_reconciler.New(ctx, clusters, clusterProjectID, tenantDomain, tenantName, billingAccount, aliasList, config.FeatureFlags{}, google_gcp_reconciler.WithGcpServices(&google_gcp_reconciler.GcpServices{}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconcilers.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "some error") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("fail early when team has no google group email set", func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()

		apiClient, _ := apiclient.NewMockClient(t)
		reconcilers, err := google_gcp_reconciler.New(ctx, clusters, clusterProjectID, tenantDomain, tenantName, billingAccount, aliasList, config.FeatureFlags{}, google_gcp_reconciler.WithGcpServices(&google_gcp_reconciler.GcpServices{}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconcilers.Reconcile(ctx, apiClient, naisTeamWithoutGoogleGroupEmail, log); !strings.Contains(err.Error(), "no Google Workspace group exists") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("no error when we have no clusters", func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()

		apiClient, _ := apiclient.NewMockClient(t)
		reconcilers, err := google_gcp_reconciler.New(ctx, gcp.Clusters{}, clusterProjectID, tenantDomain, tenantName, billingAccount, aliasList, config.FeatureFlags{}, google_gcp_reconciler.WithGcpServices(&google_gcp_reconciler.GcpServices{}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconcilers.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("full reconcile, no existing project state", func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()

		clusters := gcp.Clusters{
			env: gcp.Cluster{
				TeamsFolderID: teamFolderID,
				ProjectID:     clusterProjectID,
			},
		}
		expectedTeamProjectID := "slug-prod-ea99"
		expectedCNRMRoleId := "CustomCNRMRole"
		expectedTeamRoleId := "CustomTeamRole"
		expectedCnrmRoleName := "projects/slug-prod-ea99/roles/" + expectedCNRMRoleId
		expectedTeamRoleName := "projects/slug-prod-ea99/roles/" + expectedTeamRoleId
		flags := config.FeatureFlags{
			AttachSharedVpc: true,
		}

		apiClient, mockServer := apiclient.NewMockClient(t)

		mockServer.Teams.EXPECT().
			Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Slug: teamSlug, Limit: 100}).
			Return(&protoapi.ListTeamEnvironmentsResponse{
				Nodes: []*protoapi.TeamEnvironment{
					{Gcp: true, EnvironmentName: env},
				},
			}, nil).
			Once()
		mockServer.Teams.EXPECT().
			SetTeamEnvironmentExternalReferences(mock.Anything, &protoapi.SetTeamEnvironmentExternalReferencesRequest{
				Slug:            teamSlug,
				EnvironmentName: env,
				GcpProjectId:    &expectedTeamProjectID,
			}).
			Return(&protoapi.SetTeamEnvironmentExternalReferencesResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			SetTeamEnvironmentExternalReferences(mock.Anything, &protoapi.SetTeamEnvironmentExternalReferencesRequest{
				Slug:            teamSlug,
				EnvironmentName: "prodalias",
				GcpProjectId:    &expectedTeamProjectID,
			}).
			Return(&protoapi.SetTeamEnvironmentExternalReferencesResponse{}, nil).
			Once()

		srv := test.HttpServerWithHandlers(t, []http.HandlerFunc{
			// create project request
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got: %q", r.Method)
				}
				payload := cloudresourcemanager.Project{}
				_ = json.NewDecoder(r.Body).Decode(&payload)
				if payload.DisplayName != "slug-prod" {
					t.Errorf("expected display name %q, got %q", "slug-prod", payload.DisplayName)
				}

				if payload.Parent != "folders/123" {
					t.Errorf("expected parent %q, got %q", "folders/123", payload.Parent)
				}

				if payload.ProjectId != expectedTeamProjectID {
					t.Errorf("expected project id %q, got %q", expectedTeamProjectID, payload.ProjectId)
				}

				project := cloudresourcemanager.Project{
					Name:      payload.DisplayName,
					ProjectId: payload.ProjectId,
				}
				projectJson, _ := project.MarshalJSON()

				op := cloudresourcemanager.Operation{
					Done:     true,
					Response: projectJson,
				}
				resp, _ := op.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// set project labels
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPatch {
					t.Errorf("expected HTTP PATCH, got: %q", r.Method)
				}
				payload := cloudresourcemanager.Project{}
				_ = json.NewDecoder(r.Body).Decode(&payload)

				if payload.Labels["environment"] != env {
					t.Errorf("expected environment %q, got %q", env, payload.Labels["environment"])
				}

				if payload.Labels["team"] != teamSlug {
					t.Errorf("expected team %q, got %q", teamSlug, payload.Labels["team"])
				}

				if payload.Labels["tenant"] != tenantName {
					t.Errorf("expected tenant %q, got %q", tenantName, payload.Labels["tenant"])
				}

				if payload.Labels[google_gcp_reconciler.ManagedByLabelName] != google_gcp_reconciler.ManagedByLabelValue {
					t.Errorf("expected managed by label %q, got %q", google_gcp_reconciler.ManagedByLabelValue, payload.Labels[google_gcp_reconciler.ManagedByLabelName])
				}

				project, _ := payload.MarshalJSON()
				op := cloudresourcemanager.Operation{
					Done:     true,
					Response: project,
				}
				resp, _ := op.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// get existing billing info
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected HTTP GET, got: %q", r.Method)
				}
				info := cloudbilling.ProjectBillingInfo{}
				resp, _ := info.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// update billing info
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut {
					t.Errorf("expected HTTP PUT, got: %q", r.Method)
				}
				payload := cloudbilling.ProjectBillingInfo{}
				_ = json.NewDecoder(r.Body).Decode(&payload)

				if payload.BillingAccountName != billingAccount {
					t.Errorf("expected billing account %q, got %q", billingAccount, payload.BillingAccountName)
				}

				info := cloudbilling.ProjectBillingInfo{}
				resp, _ := info.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// get existing CNRM service account
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected HTTP GET, got: %q", r.Method)
				}
				w.WriteHeader(404)
			},

			// create CNRM service account
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got: %q", r.Method)
				}
				payload := iam.CreateServiceAccountRequest{}
				_ = json.NewDecoder(r.Body).Decode(&payload)

				if expected := "nais-sa-cnrm"; payload.AccountId != expected {
					t.Errorf("expected account id %q, got %q", expected, payload.AccountId)
				}

				if expected := "CNRM service account"; payload.ServiceAccount.DisplayName != expected {
					t.Errorf("expected display name %q, got %q", expected, payload.ServiceAccount.DisplayName)
				}

				sa := iam.ServiceAccount{
					Name:  "projects/some-project-123/serviceAccounts/cnrm@some-project-123.iam.gserviceaccount.com",
					Email: "cnrm@some-project-123.iam.gserviceaccount.com",
				}
				resp, _ := sa.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// get existing custom CNRM role
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected HTTP GET, got: %q", r.Method)
				}
				w.WriteHeader(404)
			},

			// create custom CNRM role
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got: %q", r.Method)
				}

				payload := iam.CreateRoleRequest{}
				_ = json.NewDecoder(r.Body).Decode(&payload)

				if payload.RoleId != expectedCNRMRoleId {
					t.Errorf("expected role id %q, got %q", expectedCNRMRoleId, payload.RoleId)
				}

				if expected := 42; payload.Role.IncludedPermissions != nil && len(payload.Role.IncludedPermissions) != expected {
					t.Errorf("expected %d permissions, got %d", expected, len(payload.Role.IncludedPermissions))
				}

				payload.Role.Name = expectedCnrmRoleName

				resp, _ := payload.Role.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// get existing custom team role
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected HTTP GET, got: %q", r.Method)
				}
				w.WriteHeader(404)
			},

			// create custom team role
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got: %q", r.Method)
				}

				payload := iam.CreateRoleRequest{}
				_ = json.NewDecoder(r.Body).Decode(&payload)

				if payload.RoleId != expectedTeamRoleId {
					t.Errorf("expected role id %q, got %q", expectedTeamRoleId, payload.RoleId)
				}

				if expected := 31; payload.Role.IncludedPermissions != nil && len(payload.Role.IncludedPermissions) != expected {
					t.Errorf("expected %d permissions, got %d", expected, len(payload.Role.IncludedPermissions))
				}

				payload.Role.Name = expectedTeamRoleName

				resp, _ := payload.Role.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// set workload identity for service account
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got: %q", r.Method)
				}
				payload := iam.SetIamPolicyRequest{}
				_ = json.NewDecoder(r.Body).Decode(&payload)

				if expected := "serviceAccount:some-project-123.svc.id.goog[cnrm-system/cnrm-controller-manager-slug]"; payload.Policy.Bindings[0].Members[0] != expected {
					t.Errorf("expected member %q, got %q", expected, payload.Policy.Bindings[0].Members[0])
				}

				if payload.Policy.Bindings[0].Role != "roles/iam.workloadIdentityUser" {
					t.Errorf("expected role %q, got %q", "roles/iam.workloadIdentityUser", payload.Policy.Bindings[0].Role)
				}

				policy := iam.Policy{}
				resp, _ := policy.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// get existing IAM policy for the team project
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got: %q", r.Method)
				}
				policy := iam.Policy{}
				resp, _ := policy.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// set updated IAM policy for the team project
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got: %q", r.Method)
				}
				payload := iam.SetIamPolicyRequest{}
				_ = json.NewDecoder(r.Body).Decode(&payload)
				expectedBindings := map[string]string{
					payload.Policy.Bindings[0].Role: payload.Policy.Bindings[0].Members[0],
					payload.Policy.Bindings[1].Role: payload.Policy.Bindings[1].Members[0],
				}

				if expectedBindings[expectedCnrmRoleName] != "serviceAccount:cnrm@some-project-123.iam.gserviceaccount.com" {
					t.Errorf("incorrect owner, expected: %q, got: %q", "serviceAccount:cnrm@some-project-123.iam.gserviceaccount.com", expectedBindings[expectedCnrmRoleName])
				}

				policy := iam.Policy{}
				resp, _ := policy.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// list existing Google APIs for the team project
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected HTTP GET, got: %q", r.Method)
				}
				services := serviceusage.ListServicesResponse{}
				resp, _ := services.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// enable Google APIs for the team project
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got: %q", r.Method)
				}
				payload := serviceusage.BatchEnableServicesRequest{}
				_ = json.NewDecoder(r.Body).Decode(&payload)

				if len(payload.ServiceIds) != numberOfAPIs {
					t.Errorf("expected %d services, got %d", numberOfAPIs, len(payload.ServiceIds))
				}

				op := serviceusage.Operation{Done: true}
				resp, _ := op.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// list firewall rules for project
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected HTTP GET, got: %q", r.Method)
				}

				if expected := "/projects/" + expectedTeamProjectID + "/global/firewalls"; r.URL.Path != expected {
					t.Errorf("expected path %q, got %q", expected, r.URL.Path)
				}

				list := compute.FirewallList{
					Items: []*compute.Firewall{
						{
							Name:     "default-allow-ssh",
							Priority: 65534,
						},
					},
				}

				resp, _ := list.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// delete default firewall rule
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected HTTP DELETE, got: %q", r.Method)
				}

				if expected := "/projects/" + expectedTeamProjectID + "/global/firewalls/default-allow-ssh"; r.URL.Path != expected {
					t.Errorf("expected path %q, got %q", expected, r.URL.Path)
				}

				op := compute.Operation{Name: "operation-name", Status: "RUNNING"}
				resp, _ := op.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// wait for operation to complete
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got: %q", r.Method)
				}

				if expected := "/projects/" + expectedTeamProjectID + "/global/operations/operation-name/wait"; r.URL.Path != expected {
					t.Errorf("expected path %q, got %q", expected, r.URL.Path)
				}

				op := compute.Operation{Name: "operation-name", Status: "DONE"}
				resp, _ := op.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// get team projects attached to shared vpc
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected HTTP GET, got: %q", r.Method)
				}

				if expected := "/projects/" + clusterProjectID + "/getXpnResources"; r.URL.Path != expected {
					t.Errorf("expected path %q, got %q", expected, r.URL.Path)
				}

				getXpnResources := compute.ProjectsGetXpnResources{
					Resources: []*compute.XpnResourceId{},
				}
				resp, _ := getXpnResources.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// attach team project to shared vpc
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got: %q", r.Method)
				}

				if expected := "/projects/" + clusterProjectID + "/enableXpnResource"; r.URL.Path != expected {
					t.Errorf("expected path %q, got %q", expected, r.URL.Path)
				}

				op := compute.Operation{Name: "operation-name-enable-xpn-resource", Status: "RUNNING"}
				resp, _ := op.MarshalJSON()
				_, _ = w.Write(resp)
			},

			// wait for operation to complete
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got: %q", r.Method)
				}

				if expected := "/projects/" + clusterProjectID + "/global/operations/operation-name-enable-xpn-resource/wait"; r.URL.Path != expected {
					t.Errorf("expected path %q, got %q", expected, r.URL.Path)
				}

				op := compute.Operation{Name: "operation-name-enable-xpn-resource", Status: "DONE"}
				resp, _ := op.MarshalJSON()
				_, _ = w.Write(resp)
			},
		})
		defer srv.Close()

		cloudBillingService, _ := cloudbilling.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(srv.URL))
		cloudResourceManagerService, _ := cloudresourcemanager.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(srv.URL))
		iamService, _ := iam.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(srv.URL))
		serviceUsageService, _ := serviceusage.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(srv.URL))
		computeService, _ := compute.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(srv.URL))

		gcpServices := &google_gcp_reconciler.GcpServices{
			CloudBillingProjectsService:           cloudBillingService.Projects,
			CloudResourceManagerProjectsService:   cloudResourceManagerService.Projects,
			CloudResourceManagerOperationsService: cloudResourceManagerService.Operations,
			IamProjectsServiceAccountsService:     iamService.Projects.ServiceAccounts,
			ServiceUsageService:                   serviceUsageService.Services,
			ServiceUsageOperationsService:         serviceUsageService.Operations,
			FirewallService:                       computeService.Firewalls,
			ComputeGlobalOperationsService:        computeService.GlobalOperations,
			ComputeProjectsService:                computeService.Projects,
			ProjectsRolesService:                  iamService.Projects.Roles,
		}

		reconcilers, err := google_gcp_reconciler.New(ctx, clusters, clusterProjectID, tenantDomain, tenantName, billingAccount, aliasList, flags, google_gcp_reconciler.WithGcpServices(gcpServices))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconcilers.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestDelete(t *testing.T) {
	t.Run("fail early when unable to load reconciler state", func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Slug: teamSlug, Limit: 100}).
			Return(nil, fmt.Errorf("some error")).
			Once()
		reconcilers, err := google_gcp_reconciler.New(ctx, clusters, clusterProjectID, tenantDomain, tenantName, billingAccount, aliasList, config.FeatureFlags{}, google_gcp_reconciler.WithGcpServices(&google_gcp_reconciler.GcpServices{}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconcilers.Delete(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "some error") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("remove state when it does not refer to any projects", func(t *testing.T) {
		log, hook := logrustest.NewNullLogger()

		apiClient, mockServer := apiclient.NewMockClient(t)

		mockServer.Teams.EXPECT().
			Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Slug: teamSlug, Limit: 100}).
			Return(&protoapi.ListTeamEnvironmentsResponse{
				Nodes: []*protoapi.TeamEnvironment{
					{Gcp: true, EnvironmentName: env},
				},
			}, nil).
			Once()

		reconcilers, err := google_gcp_reconciler.New(ctx, clusters, clusterProjectID, tenantDomain, tenantName, billingAccount, aliasList, config.FeatureFlags{}, google_gcp_reconciler.WithGcpServices(&google_gcp_reconciler.GcpServices{}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconcilers.Delete(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(hook.Entries) != 1 {
			t.Fatalf("expected one log entry, got %d", len(hook.Entries))
		}

		if actual := hook.LastEntry().Level; actual != logrus.WarnLevel {
			t.Fatalf("expected log level %v, got %v", logrus.WarnLevel, actual)
		}

		if !strings.Contains(hook.LastEntry().Message, "skipping environment, no GCP project or project is already deleted") {
			t.Fatalf("unexpected log message: %v", hook.LastEntry().Message)
		}
	})

	t.Run("full delete", func(t *testing.T) {
		// TODO: implement
	})
}

func TestGenerateProjectID(t *testing.T) {
	tests := []struct {
		expected string
		domain   string
		env      string
		slug     string
	}{
		// different organization names don't show up in name, but are reflected in the hash
		{"happyteam-prod-488a", "nais.io", "production", "happyteam"},
		{"happyteam-prod-5534", "bais.io", "production", "happyteam"},

		// environments that get truncated produce different hashes
		{"sadteam-prod-04d4", "nais.io", "production", "sadteam"},
		{"sadteam-prod-6ce6", "nais.io", "producers", "sadteam"},

		// team names that get truncated produce different hashes
		{"happyteam-is-very-ha-prod-4b2d", "bais.io", "production", "happyteam-is-very-happy"},
		{"happyteam-is-very-ha-prod-4801", "bais.io", "production", "happyteam-is-very-happy-and-altogether-too-long"},

		// project id with double hyphens
		{"hapyteam-is-very-ha-prod-fd5d", "bais.io", "production", "hapyteam-is-very-ha-a"},

		// environment with hyphen as 4th character in environment
		{"hapyteam-is-happy-pro-2a15", "bais.io", "pro-duction", "hapyteam-is-happy"},
	}

	for _, tt := range tests {
		if actual := google_gcp_reconciler.GenerateProjectID(tt.domain, tt.env, tt.slug); tt.expected != actual {
			t.Errorf("expected %q, got %q", tt.expected, actual)
		}
	}
}

func TestGetProjectDisplayName(t *testing.T) {
	tests := []struct {
		slug     string
		env      string
		expected string
	}{
		{"some-slug", "prod", "some-slug-prod"},
		{"some-slug", "production", "some-slug-production"},
		{"some-verry-unnecessarily-long-slug", "dev", "some-verry-unnecessarily-l-dev"},
		{"some-verry-unnecessarily-long-slug", "prod", "some-verry-unnecessarily-prod"},
	}
	for _, tt := range tests {
		if actual := google_gcp_reconciler.GetProjectDisplayName(tt.slug, tt.env); tt.expected != actual {
			t.Errorf("expected %q, got %q", tt.expected, actual)
		}
	}
}
