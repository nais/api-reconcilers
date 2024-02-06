package google_gar_reconciler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	"cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	github_team_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/github/team"
	google_gar_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/gar"
	"github.com/nais/api-reconcilers/internal/test"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	statusproto "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type fakeArtifactRegistry struct {
	createCounter int
	create        func(ctx context.Context, r *artifactregistrypb.CreateRepositoryRequest) (*longrunningpb.Operation, error)

	getCounter int
	get        func(ctx context.Context, r *artifactregistrypb.GetRepositoryRequest) (*artifactregistrypb.Repository, error)

	updateCounter int
	update        func(ctx context.Context, r *artifactregistrypb.UpdateRepositoryRequest) (*artifactregistrypb.Repository, error)

	deleteCounter int
	delete        func(ctx context.Context, r *artifactregistrypb.DeleteRepositoryRequest) (*longrunningpb.Operation, error)

	setIamPolicy        func(context.Context, *iampb.SetIamPolicyRequest) (*iampb.Policy, error)
	setIamPolicyCounter int

	artifactregistrypb.UnimplementedArtifactRegistryServer
}

type mocks struct {
	artifactRegistry *fakeArtifactRegistry
	iam              *httptest.Server
}

func (f *fakeArtifactRegistry) CreateRepository(ctx context.Context, r *artifactregistrypb.CreateRepositoryRequest) (*longrunningpb.Operation, error) {
	f.createCounter++
	return f.create(ctx, r)
}

func (f *fakeArtifactRegistry) GetRepository(ctx context.Context, r *artifactregistrypb.GetRepositoryRequest) (*artifactregistrypb.Repository, error) {
	f.getCounter++
	return f.get(ctx, r)
}

func (f *fakeArtifactRegistry) UpdateRepository(ctx context.Context, r *artifactregistrypb.UpdateRepositoryRequest) (*artifactregistrypb.Repository, error) {
	f.updateCounter++
	return f.update(ctx, r)
}

func (f *fakeArtifactRegistry) DeleteRepository(ctx context.Context, r *artifactregistrypb.DeleteRepositoryRequest) (*longrunningpb.Operation, error) {
	f.deleteCounter++
	return f.delete(ctx, r)
}

func (f *fakeArtifactRegistry) SetIamPolicy(ctx context.Context, r *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	f.setIamPolicyCounter++
	return f.setIamPolicy(ctx, r)
}

func (f *fakeArtifactRegistry) assert(t *testing.T) {
	if f.create != nil {
		assert.Equal(t, f.createCounter, 1, "mock expected 1 call to create")
	}
	if f.update != nil {
		assert.Equal(t, f.updateCounter, 1, "mock expected 1 call to update")
	}
	if f.get != nil {
		assert.Equal(t, f.getCounter, 1, "mock expected 1 call to get")
	}
	if f.delete != nil {
		assert.Equal(t, f.deleteCounter, 1, "mock expected 1 call to delete")
	}
	if f.setIamPolicy != nil {
		assert.Equal(t, f.setIamPolicyCounter, 1, "mock expected 1 call to setIamPolicy")
	}
}

func (m *mocks) start(t *testing.T, ctx context.Context) (*artifactregistry.Client, *iam.Service) {
	t.Helper()

	var artifactRegistryClient *artifactregistry.Client
	if m.artifactRegistry != nil {
		l, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		srv := grpc.NewServer()
		artifactregistrypb.RegisterArtifactRegistryServer(srv, m.artifactRegistry)
		go func() {
			if err := srv.Serve(l); err != nil {
				panic(err)
			}
		}()
		t.Cleanup(func() {
			m.artifactRegistry.assert(t)
			srv.Stop()
		})

		artifactRegistryClient, err = artifactregistry.NewClient(ctx,
			option.WithEndpoint(l.Addr().String()),
			option.WithoutAuthentication(),
			option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
		)
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

	return artifactRegistryClient, iamService
}

func TestReconcile(t *testing.T) {
	const (
		tenantDomain             = "example.com"
		managementProjectID      = "management-project-123"
		workloadIdentityPoolName = "projects/123456789/locations/global/workloadIdentityPools/some-identity-pool"
		abortReconcilerCode      = 418
		groupEmail               = "team@example.com"
		teamSlug                 = "team"
	)

	abortTestErr := fmt.Errorf("abort test")

	naisTeam := &protoapi.Team{
		Slug: teamSlug,
	}

	email := fmt.Sprintf("%s@%s.iam.gserviceaccount.com", teamSlug, managementProjectID)
	expectedServiceAccount := &iam.ServiceAccount{
		Email:       email,
		Name:        fmt.Sprintf("projects/%s/serviceAccounts/%s", managementProjectID, email),
		Description: fmt.Sprintf("Service Account used to push images to Google Artifact Registry for %s", teamSlug),
		DisplayName: fmt.Sprintf("Artifact Pusher for %s", teamSlug),
	}

	garRepositoryParent := fmt.Sprintf("projects/%s/locations/europe-north1", managementProjectID)
	expectedRepository := artifactregistrypb.Repository{
		Name:        fmt.Sprintf("%s/repositories/%s", garRepositoryParent, teamSlug),
		Format:      artifactregistrypb.Repository_DOCKER,
		Description: fmt.Sprintf("Docker repository for team %q. Managed by github.com/nais/api-reconcilers.", teamSlug),
		Labels: map[string]string{
			"team":       teamSlug,
			"managed-by": "api-reconcilers",
		},
	}

	ctx := context.Background()
	log, _ := logrustest.NewNullLogger()

	t.Run("when service account does not exist, create it", func(t *testing.T) {
		mocks := mocks{
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(404)
				},
				func(w http.ResponseWriter, r *http.Request) {
					var req iam.CreateServiceAccountRequest
					assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))
					assert.Equal(t, expectedServiceAccount.Description, req.ServiceAccount.Description)
					assert.Equal(t, expectedServiceAccount.DisplayName, req.ServiceAccount.DisplayName)
					w.WriteHeader(abortReconcilerCode) // abort test - we have asserted what we are interested in already
				},
			}),
		}
		_, iamService := mocks.start(t, ctx)

		apiClient, _ := apiclient.NewMockClient(t)

		reconciler, err := google_gar_reconciler.New(ctx, managementProjectID, tenantDomain, workloadIdentityPoolName, google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), fmt.Sprintf("googleapi: got HTTP response code %d", abortReconcilerCode)) {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("after getOrCreateServiceAccount, set policy", func(t *testing.T) {
		mocks := mocks{
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				func(w http.ResponseWriter, r *http.Request) {
					assert.NoError(t, json.NewEncoder(w).Encode(&expectedServiceAccount))
				},
				func(w http.ResponseWriter, r *http.Request) {
					var req iam.SetIamPolicyRequest
					prefix := "principalSet://iam.googleapis.com/" + workloadIdentityPoolName + "/attribute.repository"
					assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))
					assert.Contains(t, r.URL.Path, expectedServiceAccount.Name)
					assert.Contains(t, req.Policy.Bindings[0].Members, prefix+"/test/repository")
					assert.Contains(t, req.Policy.Bindings[0].Members, prefix+"/test/admin-repository")
					assert.NotContains(t, req.Policy.Bindings[0].Members, prefix+"/test/ro-repository")
					assert.NotContains(t, req.Policy.Bindings[0].Members, prefix+"/test/no-permissions-repository")
					assert.NotContains(t, req.Policy.Bindings[0].Members, prefix+"/test/archived-repository")
					w.WriteHeader(abortReconcilerCode)
				},
			}),
		}
		_, iamService := mocks.start(t, ctx)

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{
				Nodes: []*protoapi.ReconcilerResource{
					{
						Name:  "repo",
						Value: "test/repository",
						Metadata: toJson(&github_team_reconciler.GitHubRepository{
							Permissions: []*github_team_reconciler.GitHubRepositoryPermission{
								{Name: "push", Granted: true},
							},
						}),
					},
					{
						Name:  "repo",
						Value: "test/ro-repository",
						Metadata: toJson(&github_team_reconciler.GitHubRepository{
							Permissions: []*github_team_reconciler.GitHubRepositoryPermission{
								{Name: "push", Granted: false},
							},
						}),
					},
					{
						Name:  "repo",
						Value: "test/admin-repository",
						Metadata: toJson(&github_team_reconciler.GitHubRepository{
							Permissions: []*github_team_reconciler.GitHubRepositoryPermission{
								{Name: "push", Granted: true},
								{Name: "admin", Granted: true},
							},
						}),
					},
					{
						Name:  "repo",
						Value: "test/archived-repository",
						Metadata: toJson(&github_team_reconciler.GitHubRepository{
							Permissions: []*github_team_reconciler.GitHubRepositoryPermission{
								{Name: "push", Granted: true},
								{Name: "admin", Granted: true},
							},
							Archived: true,
						}),
					},
					{
						Name:     "repo",
						Value:    "test/no-permissions-repository",
						Metadata: toJson(&github_team_reconciler.GitHubRepository{}),
					},
				},
			}, nil).
			Once()

		reconciler, err := google_gar_reconciler.New(ctx, managementProjectID, tenantDomain, workloadIdentityPoolName, google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), fmt.Sprintf("googleapi: got HTTP response code %d", abortReconcilerCode)) {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("if no gar repository exists, create it", func(t *testing.T) {
		mocks := mocks{
			artifactRegistry: &fakeArtifactRegistry{
				get: func(ctx context.Context, r *artifactregistrypb.GetRepositoryRequest) (*artifactregistrypb.Repository, error) {
					return nil, status.Error(codes.NotFound, "not found")
				},
				create: func(ctx context.Context, r *artifactregistrypb.CreateRepositoryRequest) (*longrunningpb.Operation, error) {
					assert.Equal(t, r.Repository.Name, expectedRepository.Name)
					assert.Equal(t, r.Repository.Description, expectedRepository.Description)
					assert.Equal(t, r.Parent, garRepositoryParent)
					assert.Equal(t, r.Repository.Format, expectedRepository.Format)

					payload := anypb.Any{}
					err := anypb.MarshalFrom(&payload, r.Repository, proto.MarshalOptions{})
					assert.NoError(t, err)

					return &longrunningpb.Operation{
						Done: true,
						Result: &longrunningpb.Operation_Response{
							Response: &payload,
						},
					}, abortTestErr
				},
			},
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get service account
				func(w http.ResponseWriter, r *http.Request) {
					assert.NoError(t, json.NewEncoder(w).Encode(expectedServiceAccount))
				},
				// set iam policy
				func(w http.ResponseWriter, r *http.Request) {
					assert.NoError(t, json.NewEncoder(w).Encode(&iam.Policy{}))
				},
			}),
		}
		artifactregistryClient, iamService := mocks.start(t, ctx)

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{}, nil).
			Once()

		reconciler, err := google_gar_reconciler.New(ctx, managementProjectID, tenantDomain, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(artifactregistryClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "abort test") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("if gar repository exists, set iam policy", func(t *testing.T) {
		mocks := mocks{
			artifactRegistry: &fakeArtifactRegistry{
				get: func(ctx context.Context, r *artifactregistrypb.GetRepositoryRequest) (*artifactregistrypb.Repository, error) {
					return &expectedRepository, nil
				},
				setIamPolicy: func(ctx context.Context, r *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
					assert.Equal(t, expectedRepository.Name, r.Resource)
					assert.Len(t, r.Policy.Bindings, 2)
					assert.Len(t, r.Policy.Bindings[0].Members, 1)
					assert.Len(t, r.Policy.Bindings[1].Members, 1)

					assert.Equal(t, "serviceAccount:"+expectedServiceAccount.Email, r.Policy.Bindings[0].Members[0])
					assert.Equal(t, "roles/artifactregistry.writer", r.Policy.Bindings[0].Role)

					assert.Equal(t, "group:"+groupEmail, r.Policy.Bindings[1].Members[0])
					assert.Equal(t, "roles/artifactregistry.repoAdmin", r.Policy.Bindings[1].Role)

					return &iampb.Policy{}, nil
				},
			},
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get service account
				func(w http.ResponseWriter, r *http.Request) {
					assert.NoError(t, json.NewEncoder(w).Encode(expectedServiceAccount))
				},
				// set iam policy
				func(w http.ResponseWriter, r *http.Request) {
					assert.NoError(t, json.NewEncoder(w).Encode(&iam.Policy{}))
				},
			}),
		}

		naisTeam := naisTeam
		naisTeam.GoogleGroupEmail = groupEmail
		naisTeam.GarRepository = garRepositoryParent + "/repositories/" + teamSlug

		artifactregistryClient, iamService := mocks.start(t, ctx)

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			SetTeamExternalReferences(mock.Anything, mock.MatchedBy(func(req *protoapi.SetTeamExternalReferencesRequest) bool {
				return req.Slug == teamSlug && *req.GarRepository == garRepositoryParent+"/repositories/"+teamSlug
			})).
			Return(&protoapi.SetTeamExternalReferencesResponse{}, nil).
			Once()
		mockServer.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{}, nil).
			Once()

		reconciler, err := google_gar_reconciler.New(ctx, managementProjectID, tenantDomain, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(artifactregistryClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("gar repository exists, but has outdated info", func(t *testing.T) {
		mocks := mocks{
			artifactRegistry: &fakeArtifactRegistry{
				get: func(ctx context.Context, r *artifactregistrypb.GetRepositoryRequest) (*artifactregistrypb.Repository, error) {
					assert.Equal(t, expectedRepository.Name, r.Name)

					repo := expectedRepository
					repo.Description = "some incorrect description"
					repo.Labels = map[string]string{
						"team": "some-incorrect-team",
					}
					return &repo, nil
				},
				update: func(ctx context.Context, r *artifactregistrypb.UpdateRepositoryRequest) (*artifactregistrypb.Repository, error) {
					assert.Equal(t, expectedRepository.Description, r.Repository.Description)
					assert.Equal(t, expectedRepository.Name, r.Repository.Name)
					assert.Equal(t, teamSlug, r.Repository.Labels["team"])

					return nil, abortTestErr
				},
			},
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get service account
				func(w http.ResponseWriter, r *http.Request) {
					assert.NoError(t, json.NewEncoder(w).Encode(expectedServiceAccount))
				},
				// set iam policy
				func(w http.ResponseWriter, r *http.Request) {
					assert.NoError(t, json.NewEncoder(w).Encode(&iam.Policy{}))
				},
			}),
		}

		artifactregistryClient, iamService := mocks.start(t, ctx)

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{}, nil).
			Once()

		reconciler, err := google_gar_reconciler.New(ctx, managementProjectID, tenantDomain, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(artifactregistryClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "abort test") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestDelete(t *testing.T) {
	ctx := context.Background()

	const (
		tenantDomain             = "example.com"
		managementProjectID      = "management-project-123"
		workloadIdentityPoolName = "projects/123456789/locations/global/workloadIdentityPools/some-identity-pool"
		repositoryName           = "some-repo-name-123"
		teamSlug                 = "my-team"
	)

	log, hook := logrustest.NewNullLogger()

	naisTeam := &protoapi.Team{
		Slug: teamSlug,
	}

	t.Run("team is missing repository name", func(t *testing.T) {
		defer hook.Reset()

		apiClient, _ := apiclient.NewMockClient(t)

		reconciler, err := google_gar_reconciler.New(ctx, managementProjectID, tenantDomain, workloadIdentityPoolName)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Delete(ctx, apiClient, naisTeam, log); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(hook.Entries) != 1 {
			t.Fatalf("unexpected a single log entry")
		}

		if hook.Entries[0].Level != logrus.WarnLevel {
			t.Errorf("unexpected log level: %v", hook.Entries[0].Level)
		}

		if !strings.Contains(hook.Entries[0].Message, "missing repository name in team") {
			t.Errorf("unexpected log message: %v", hook.Entries[0].Message)
		}
	})

	t.Run("delete service account fails with unexpected error", func(t *testing.T) {
		naisTeam := naisTeam
		naisTeam.GarRepository = repositoryName
		apiClient, _ := apiclient.NewMockClient(t)

		mockedClients := mocks{
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				func(w http.ResponseWriter, r *http.Request) {
					assert.Contains(t, r.URL.Path, "management-project-123/serviceAccounts/gar-my-team-a193@management-project-123.iam.gserviceaccount.com")
					w.WriteHeader(http.StatusInternalServerError)
				},
			}),
		}
		garClient, iamService := mockedClients.start(t, ctx)

		reconciler, err := google_gar_reconciler.New(ctx, managementProjectID, tenantDomain, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(garClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Delete(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "delete service account") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("service account does not exist, and delete repo request fails", func(t *testing.T) {
		defer hook.Reset()

		apiClient, _ := apiclient.NewMockClient(t)
		// mockServer.ReconcilerResources.EXPECT().
		// 	List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "google:gcp:gar", TeamSlug: teamSlug}).
		// 	Return(&protoapi.ListReconcilerResourcesResponse{
		// 		Nodes: []*protoapi.ReconcilerResource{
		// 			{
		// 				Name:  "repository_name",
		// 				Value: repositoryName,
		// 			},
		// 		},
		// 	}, nil).
		// 	Once()

		mockedClients := mocks{
			artifactRegistry: &fakeArtifactRegistry{
				delete: func(ctx context.Context, req *artifactregistrypb.DeleteRepositoryRequest) (*longrunningpb.Operation, error) {
					return nil, fmt.Errorf("some error")
				},
			},
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				},
			}),
		}
		garClient, iamService := mockedClients.start(t, ctx)

		reconciler, err := google_gar_reconciler.New(ctx, managementProjectID, tenantDomain, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(garClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Delete(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "delete GAR repository for team") {
			t.Errorf("unexpected error: %v", err)
		}

		if len(hook.Entries) != 1 {
			t.Fatalf("unexpected a single log entry")
		}

		if !strings.Contains(hook.Entries[0].Message, "does not exist") {
			t.Errorf("unexpected log message: %v", hook.Entries[0].Message)
		}
	})

	t.Run("delete repo operation fails", func(t *testing.T) {
		apiClient, _ := apiclient.NewMockClient(t)

		mockedClients := mocks{
			artifactRegistry: &fakeArtifactRegistry{
				delete: func(ctx context.Context, req *artifactregistrypb.DeleteRepositoryRequest) (*longrunningpb.Operation, error) {
					return &longrunningpb.Operation{
						Done: true,
						Result: &longrunningpb.Operation_Error{
							Error: &statusproto.Status{
								Code:    int32(codes.NotFound),
								Message: "not found",
							},
						},
					}, nil
				},
			},
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				},
			}),
		}
		garClient, iamService := mockedClients.start(t, ctx)

		reconciler, err := google_gar_reconciler.New(ctx, managementProjectID, tenantDomain, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(garClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Delete(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "wait for GAR repository deletion") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("successful delete", func(t *testing.T) {
		defer hook.Reset()

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			SetTeamExternalReferences(mock.Anything, mock.MatchedBy(func(req *protoapi.SetTeamExternalReferencesRequest) bool {
				return req.Slug == teamSlug && *req.GarRepository == ""
			})).
			Return(&protoapi.SetTeamExternalReferencesResponse{}, nil).
			Once()

		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "google:gar:delete"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		mockedClients := mocks{
			artifactRegistry: &fakeArtifactRegistry{
				delete: func(ctx context.Context, req *artifactregistrypb.DeleteRepositoryRequest) (*longrunningpb.Operation, error) {
					assert.Equal(t, repositoryName, req.Name)
					return &longrunningpb.Operation{
						Done:   true,
						Result: &longrunningpb.Operation_Response{},
					}, nil
				},
			},
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				},
			}),
		}
		garClient, iamService := mockedClients.start(t, ctx)

		reconciler, err := google_gar_reconciler.New(ctx, managementProjectID, tenantDomain, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(garClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Delete(ctx, apiClient, naisTeam, log); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func toJson(r *github_team_reconciler.GitHubRepository) []byte {
	j, _ := json.Marshal(r)
	return j
}
