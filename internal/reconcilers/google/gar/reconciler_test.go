package google_gar_reconciler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	"cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
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
	"k8s.io/utils/ptr"

	google_gar_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/gar"
	"github.com/nais/api-reconcilers/internal/test"
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

	getIamPolicy        func(context.Context, *iampb.GetIamPolicyRequest) (*iampb.Policy, error)
	getIamPolicyCounter int

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

func (f *fakeArtifactRegistry) GetIamPolicy(ctx context.Context, r *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	f.getIamPolicyCounter++
	return f.getIamPolicy(ctx, r)
}

func (f *fakeArtifactRegistry) assert(t *testing.T) {
	if f.create != nil && f.createCounter != 1 {
		t.Errorf("mock expected 1 call to create, got %d", f.createCounter)
	}
	if f.update != nil && f.updateCounter != 1 {
		t.Errorf("mock expected 1 call to update, got %d", f.updateCounter)
	}
	if f.get != nil && f.getCounter != 1 {
		t.Errorf("mock expected 1 call to get, got %d", f.getCounter)
	}
	if f.delete != nil && f.deleteCounter != 1 {
		t.Errorf("mock expected 1 call to delete, got %d", f.deleteCounter)
	}
	if f.setIamPolicy != nil && f.setIamPolicyCounter != 1 {
		t.Errorf("mock expected 1 call to setIamPolicy, got %d", f.setIamPolicyCounter)
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
		managementProjectID      = "management-project-123"
		workloadIdentityPoolName = "projects/123456789/locations/global/workloadIdentityPools/some-identity-pool"
		abortReconcilerCode      = 418
		groupEmail               = "team@example.com"
		teamSlug                 = "team"
		serviceAccountEmail      = "sa@example.com"
	)

	abortTestErr := fmt.Errorf("abort test")

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
		CleanupPolicies: google_gar_reconciler.DefaultCleanupPolicies(),
	}

	ctx := context.Background()
	log, _ := logrustest.NewNullLogger()

	t.Run("when service account does not exist, create it", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug: teamSlug,
		}

		mocks := mocks{
			artifactRegistry: &fakeArtifactRegistry{},
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(404)
				},
				func(w http.ResponseWriter, r *http.Request) {
					var req iam.CreateServiceAccountRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					if req.ServiceAccount.Description != expectedServiceAccount.Description {
						t.Errorf("expected description %q, got %q", expectedServiceAccount.Description, req.ServiceAccount.Description)
					}

					if req.ServiceAccount.DisplayName != expectedServiceAccount.DisplayName {
						t.Errorf("expected display name %q, got %q", expectedServiceAccount.DisplayName, req.ServiceAccount.DisplayName)
					}
					w.WriteHeader(abortReconcilerCode) // abort test - we have asserted what we are interested in already
				},
			}),
		}
		artifactRegistryClient, iamService := mocks.start(t, ctx)

		apiClient, _ := apiclient.NewMockClient(t)

		reconciler, err := google_gar_reconciler.New(ctx, serviceAccountEmail, managementProjectID, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(artifactRegistryClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), fmt.Sprintf("googleapi: got HTTP response code %d", abortReconcilerCode)) {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("after getOrCreateServiceAccount, set policy", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug: teamSlug,
		}

		mocks := mocks{
			artifactRegistry: &fakeArtifactRegistry{},
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&expectedServiceAccount); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
				func(w http.ResponseWriter, r *http.Request) {
					var req iam.SetIamPolicyRequest
					prefix := "principalSet://iam.googleapis.com/" + workloadIdentityPoolName + "/attribute.repository"
					_ = json.NewDecoder(r.Body).Decode(&req)
					if contains := expectedServiceAccount.Name; !strings.Contains(r.URL.Path, contains) {
						t.Errorf("expected path to contain %q, got %q", contains, r.URL.Path)
					}

					if contains := prefix + "/test/repository"; !slices.Contains(req.Policy.Bindings[0].Members, contains) {
						t.Errorf("expected members to contain %q, got %v", contains, req.Policy.Bindings[0].Members)
					}

					if contains := prefix + "/test/admin-repository"; !slices.Contains(req.Policy.Bindings[0].Members, contains) {
						t.Errorf("expected members to contain %q, got %v", contains, req.Policy.Bindings[0].Members)
					}

					if contains := prefix + "/test/ro-repository"; slices.Contains(req.Policy.Bindings[0].Members, contains) {
						t.Errorf("did not expect members to contain %q, but it did", contains)
					}

					if contains := prefix + "/test/no-permissions-repository"; slices.Contains(req.Policy.Bindings[0].Members, contains) {
						t.Errorf("did not expect members to contain %q, but it did", contains)
					}

					if contains := prefix + "/test/archived-repository"; slices.Contains(req.Policy.Bindings[0].Members, contains) {
						t.Errorf("did not expect members to contain %q, but it did", contains)
					}

					w.WriteHeader(abortReconcilerCode)
				},
			}),
		}
		artifactregistryClient, iamService := mocks.start(t, ctx)

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			ListAuthorizedRepositories(mock.Anything, &protoapi.ListAuthorizedRepositoriesRequest{
				TeamSlug: teamSlug,
			}).
			Return(&protoapi.ListAuthorizedRepositoriesResponse{
				GithubRepositories: []string{
					"test/repository",
					"test/admin-repository",
				},
			}, nil).
			Once()

		reconciler, err := google_gar_reconciler.New(ctx, serviceAccountEmail, managementProjectID, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(artifactregistryClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), fmt.Sprintf("googleapi: got HTTP response code %d", abortReconcilerCode)) {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("if no gar repository exists, create it", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug: teamSlug,
		}

		mocks := mocks{
			artifactRegistry: &fakeArtifactRegistry{
				get: func(ctx context.Context, r *artifactregistrypb.GetRepositoryRequest) (*artifactregistrypb.Repository, error) {
					return nil, status.Error(codes.NotFound, "not found")
				},
				create: func(ctx context.Context, r *artifactregistrypb.CreateRepositoryRequest) (*longrunningpb.Operation, error) {
					if r.Repository.Name != expectedRepository.Name {
						t.Errorf("expected name %q, got %q", expectedRepository.Name, r.Repository.Name)
					}

					if r.Repository.Description != expectedRepository.Description {
						t.Errorf("expected description %q, got %q", expectedRepository.Description, r.Repository.Description)
					}

					if r.Parent != garRepositoryParent {
						t.Errorf("expected parent %q, got %q", garRepositoryParent, r.Parent)
					}

					if r.Repository.Format != expectedRepository.Format {
						t.Errorf("expected format %q, got %q", expectedRepository.Format, r.Repository.Format)
					}

					payload := anypb.Any{}
					if err := anypb.MarshalFrom(&payload, r.Repository, proto.MarshalOptions{}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}

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
					if err := json.NewEncoder(w).Encode(expectedServiceAccount); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
				// set iam policy
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&iam.Policy{}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
			}),
		}
		artifactregistryClient, iamService := mocks.start(t, ctx)

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			ListAuthorizedRepositories(mock.Anything, &protoapi.ListAuthorizedRepositoriesRequest{
				TeamSlug: teamSlug,
			}).
			Return(&protoapi.ListAuthorizedRepositoriesResponse{}, nil).
			Once()

		reconciler, err := google_gar_reconciler.New(ctx, serviceAccountEmail, managementProjectID, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(artifactregistryClient), google_gar_reconciler.WithIAMService(iamService))
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
					if r.Resource != expectedRepository.Name {
						t.Errorf("expected resource %q, got %q", expectedRepository.Name, r.Resource)
					}

					if len(r.Policy.Bindings) != 2 {
						t.Errorf("expected 2 bindings, got %d", len(r.Policy.Bindings))
					}

					if len(r.Policy.Bindings[0].Members) != 1 {
						t.Errorf("expected 1 member, got %d", len(r.Policy.Bindings[0].Members))
					}

					if len(r.Policy.Bindings[1].Members) != 1 {
						t.Errorf("expected 1 member, got %d", len(r.Policy.Bindings[1].Members))
					}

					if expected := "serviceAccount:" + expectedServiceAccount.Email; r.Policy.Bindings[1].Members[0] != expected {
						t.Errorf("expected member %q, got %q", expected, r.Policy.Bindings[1].Members[0])
					}

					if expected := "roles/artifactregistry.writer"; r.Policy.Bindings[1].Role != expected {
						t.Errorf("expected role %q, got %q", expected, r.Policy.Bindings[1].Role)
					}

					if expected := "group:" + groupEmail; r.Policy.Bindings[0].Members[0] != expected {
						t.Errorf("expected member %q, got %q", expected, r.Policy.Bindings[0].Members[0])
					}

					if expected := "roles/artifactregistry.repoAdmin"; r.Policy.Bindings[0].Role != expected {
						t.Errorf("expected role %q, got %q", expected, r.Policy.Bindings[0].Role)
					}

					return &iampb.Policy{}, nil
				},
				getIamPolicy: func(ctx context.Context, r *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
					return &iampb.Policy{}, nil
				},
			},
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get service account
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(expectedServiceAccount); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
				// set iam policy
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&iam.Policy{}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
			}),
		}

		naisTeam := &protoapi.Team{
			Slug:             teamSlug,
			GoogleGroupEmail: ptr.To(groupEmail),
			GarRepository:    ptr.To(garRepositoryParent + "/repositories/" + teamSlug),
		}

		artifactregistryClient, iamService := mocks.start(t, ctx)

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "google:gar:create"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		mockServer.Teams.EXPECT().
			SetTeamExternalReferences(mock.Anything, mock.MatchedBy(func(req *protoapi.SetTeamExternalReferencesRequest) bool {
				return req.Slug == teamSlug && *req.GarRepository == garRepositoryParent+"/repositories/"+teamSlug
			})).
			Return(&protoapi.SetTeamExternalReferencesResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			ListAuthorizedRepositories(mock.Anything, &protoapi.ListAuthorizedRepositoriesRequest{
				TeamSlug: teamSlug,
			}).
			Return(&protoapi.ListAuthorizedRepositoriesResponse{}, nil).
			Once()

		reconciler, err := google_gar_reconciler.New(ctx, serviceAccountEmail, managementProjectID, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(artifactregistryClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("gar repository exists, but has outdated info", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug: teamSlug,
		}

		mocks := mocks{
			artifactRegistry: &fakeArtifactRegistry{
				get: func(ctx context.Context, r *artifactregistrypb.GetRepositoryRequest) (*artifactregistrypb.Repository, error) {
					if r.Name != expectedRepository.Name {
						t.Errorf("expected name %q, got %q", expectedRepository.Name, r.Name)
					}

					repo := expectedRepository
					repo.Description = "some incorrect description"
					repo.Labels = map[string]string{
						"team": "some-incorrect-team",
					}
					return &repo, nil
				},
				update: func(ctx context.Context, r *artifactregistrypb.UpdateRepositoryRequest) (*artifactregistrypb.Repository, error) {
					if r.Repository.Description != expectedRepository.Description {
						t.Errorf("expected description %q, got %q", expectedRepository.Description, r.Repository.Description)
					}

					if r.Repository.Name != expectedRepository.Name {
						t.Errorf("expected name %q, got %q", expectedRepository.Name, r.Repository.Name)
					}

					if r.Repository.Labels["team"] != teamSlug {
						t.Errorf("expected team label %q, got %q", teamSlug, r.Repository.Labels["team"])
					}

					return nil, abortTestErr
				},
			},
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get service account
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(expectedServiceAccount); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
				// set iam policy
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&iam.Policy{}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
			}),
		}

		artifactregistryClient, iamService := mocks.start(t, ctx)

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			ListAuthorizedRepositories(mock.Anything, &protoapi.ListAuthorizedRepositoriesRequest{
				TeamSlug: teamSlug,
			}).
			Return(&protoapi.ListAuthorizedRepositoriesResponse{}, nil).
			Once()

		reconciler, err := google_gar_reconciler.New(ctx, serviceAccountEmail, managementProjectID, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(artifactregistryClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "abort test") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("gar repository exists, but has no cleanup policies", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug: teamSlug,
		}

		mocks := mocks{
			artifactRegistry: &fakeArtifactRegistry{
				get: func(ctx context.Context, r *artifactregistrypb.GetRepositoryRequest) (*artifactregistrypb.Repository, error) {
					repositoryWithoutCleanupPolicies := proto.Clone(&expectedRepository).(*artifactregistrypb.Repository)
					repositoryWithoutCleanupPolicies.CleanupPolicies = nil

					return repositoryWithoutCleanupPolicies, nil
				},
				update: func(ctx context.Context, r *artifactregistrypb.UpdateRepositoryRequest) (*artifactregistrypb.Repository, error) {
					if r.Repository.CleanupPolicies == nil {
						t.Errorf("expected cleanup policies to be set, got nil")
					}

					if r.Repository.CleanupPolicyDryRun {
						t.Errorf("expected cleanup policy dry run to be false, got true")
					}

					expectedPolicies := google_gar_reconciler.DefaultCleanupPolicies()
					policyUpToDate := maps.EqualFunc(expectedPolicies, r.Repository.CleanupPolicies, func(a, b *artifactregistrypb.CleanupPolicy) bool {
						return proto.Equal(a, b)
					})

					if !policyUpToDate {
						t.Errorf("expected cleanup policies to be %v, got %v", expectedPolicies, r.Repository.CleanupPolicies)
					}

					return nil, abortTestErr
				},
			},
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get service account
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(expectedServiceAccount); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
				// set iam policy
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&iam.Policy{}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
			}),
		}

		artifactregistryClient, iamService := mocks.start(t, ctx)

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			ListAuthorizedRepositories(mock.Anything, &protoapi.ListAuthorizedRepositoriesRequest{
				TeamSlug: teamSlug,
			}).
			Return(&protoapi.ListAuthorizedRepositoriesResponse{}, nil).
			Once()

		reconciler, err := google_gar_reconciler.New(ctx, serviceAccountEmail, managementProjectID, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(artifactregistryClient), google_gar_reconciler.WithIAMService(iamService))
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
		managementProjectID      = "management-project-123"
		workloadIdentityPoolName = "projects/123456789/locations/global/workloadIdentityPools/some-identity-pool"
		repositoryName           = "some-repo-name-123"
		teamSlug                 = "my-team"
		serviceAccountEmail      = "sa@example.com"
	)

	log, hook := logrustest.NewNullLogger()

	t.Run("team is missing repository name", func(t *testing.T) {
		defer hook.Reset()

		naisTeam := &protoapi.Team{
			Slug: teamSlug,
		}

		apiClient, _ := apiclient.NewMockClient(t)

		mocks := mocks{
			artifactRegistry: &fakeArtifactRegistry{},
			iam:              test.HttpServerWithHandlers(t, []http.HandlerFunc{}),
		}
		artifactregistryClient, iamService := mocks.start(t, ctx)

		reconciler, err := google_gar_reconciler.New(ctx, serviceAccountEmail, managementProjectID, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(artifactregistryClient), google_gar_reconciler.WithIAMService(iamService))
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
		naisTeam := &protoapi.Team{
			Slug:          teamSlug,
			GarRepository: ptr.To(repositoryName),
		}

		apiClient, _ := apiclient.NewMockClient(t)

		mockedClients := mocks{
			artifactRegistry: &fakeArtifactRegistry{},
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				func(w http.ResponseWriter, r *http.Request) {
					if contains := "management-project-123/serviceAccounts/gar-my-team-a193@management-project-123.iam.gserviceaccount.com"; !strings.Contains(r.URL.Path, contains) {
						t.Errorf("expected path to contain %q, got %q", contains, r.URL.Path)
					}
					w.WriteHeader(http.StatusInternalServerError)
				},
			}),
		}
		garClient, iamService := mockedClients.start(t, ctx)

		reconciler, err := google_gar_reconciler.New(ctx, serviceAccountEmail, managementProjectID, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(garClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Delete(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "delete service account") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("service account does not exist, and delete repo request fails", func(t *testing.T) {
		defer hook.Reset()

		naisTeam := &protoapi.Team{
			Slug:          teamSlug,
			GarRepository: ptr.To(repositoryName),
		}

		apiClient, _ := apiclient.NewMockClient(t)
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

		reconciler, err := google_gar_reconciler.New(ctx, serviceAccountEmail, managementProjectID, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(garClient), google_gar_reconciler.WithIAMService(iamService))
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
		naisTeam := &protoapi.Team{
			Slug:          teamSlug,
			GarRepository: ptr.To(repositoryName),
		}

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

		reconciler, err := google_gar_reconciler.New(ctx, serviceAccountEmail, managementProjectID, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(garClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Delete(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "wait for GAR repository deletion") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("successful delete", func(t *testing.T) {
		defer hook.Reset()

		naisTeam := &protoapi.Team{
			Slug:          teamSlug,
			GarRepository: ptr.To(repositoryName),
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			SetTeamExternalReferences(mock.Anything, mock.MatchedBy(func(req *protoapi.SetTeamExternalReferencesRequest) bool {
				return req.Slug == teamSlug && *req.GarRepository == ""
			})).
			Return(&protoapi.SetTeamExternalReferencesResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(req *protoapi.CreateAuditLogsRequest) bool {
				return req.ReconcilerName == "google:gcp:gar" && req.Action == "google:gar:delete"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		mockedClients := mocks{
			artifactRegistry: &fakeArtifactRegistry{
				delete: func(ctx context.Context, req *artifactregistrypb.DeleteRepositoryRequest) (*longrunningpb.Operation, error) {
					if req.Name != repositoryName {
						t.Errorf("expected name %q, got %q", repositoryName, req.Name)
					}
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

		reconciler, err := google_gar_reconciler.New(ctx, serviceAccountEmail, managementProjectID, workloadIdentityPoolName, google_gar_reconciler.WithGarClient(garClient), google_gar_reconciler.WithIAMService(iamService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Delete(ctx, apiClient, naisTeam, log); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
