package google_cdn_reconciler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	cloudcompute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"cloud.google.com/go/storage"
	google_cdn_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/cdn"
	"github.com/nais/api-reconcilers/internal/test"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	storageold "google.golang.org/api/storage/v1"
	"k8s.io/utils/ptr"
)

type mocks struct {
	backendbucket *httptest.Server
	iam           *httptest.Server
	storage       *httptest.Server
	project       *httptest.Server
	urlMap        *httptest.Server
}

func (m *mocks) start(t *testing.T, ctx context.Context) *google_cdn_reconciler.Services {
	t.Helper()

	var iamService *iam.Service
	if m.iam != nil {
		var err error
		iamService, err = iam.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(m.iam.URL))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	var storageService *storage.Client
	if m.storage != nil {
		var err error
		storageService, err = storage.NewClient(ctx, option.WithoutAuthentication(), option.WithEndpoint(m.storage.URL))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	var backendBucketService *cloudcompute.BackendBucketsClient
	if m.backendbucket != nil {
		var err error
		backendBucketService, err = cloudcompute.NewBackendBucketsRESTClient(ctx, option.WithoutAuthentication(), option.WithEndpoint(m.backendbucket.URL))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	var projectService *cloudresourcemanager.ProjectsService
	if m.project != nil {
		var err error
		cloudResourceManagerService, err := cloudresourcemanager.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(m.project.URL))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		projectService = cloudResourceManagerService.Projects
	}

	var urlMapService *compute.UrlMapsService
	if m.urlMap != nil {
		var err error
		computeService, err := compute.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(m.urlMap.URL))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		urlMapService = computeService.UrlMaps
	}

	return &google_cdn_reconciler.Services{
		BackendBuckets:               backendBucketService,
		CloudResourceManagerProjects: projectService,
		Iam:                          iamService,
		Storage:                      storageService,
		UrlMap:                       urlMapService,
	}
}

const (
	managementProjectID      = "management-project-123"
	tenantName               = "example"
	serviceAccountEmail      = "sa@example.com"
	teamSlug                 = "slug"
	googleGroupEmail         = "slug@example.com"
	workloadIdentityPoolName = "projects/123456789/locations/global/workloadIdentityPools/some-identity-pool"
)

var (
	naisTeam = &protoapi.Team{
		Slug:             teamSlug,
		GoogleGroupEmail: ptr.To(googleGroupEmail),
	}
	naisTeamWithoutGoogleGroupEmail = &protoapi.Team{
		Slug: teamSlug,
	}
	ctx = context.Background()
)

func TestReconcile(t *testing.T) {
	email := fmt.Sprintf("%s@%s.iam.gserviceaccount.com", teamSlug, managementProjectID)
	expectedServiceAccount := &iam.ServiceAccount{
		Email:       email,
		Name:        fmt.Sprintf("projects/%s/serviceAccounts/%s", managementProjectID, email),
		Description: fmt.Sprintf("service account for uploading to cdn buckets and cache invalidation for %s", teamSlug),
		DisplayName: fmt.Sprintf("CDN uploader for %s", teamSlug),
	}

	t.Run("fail early when team has no google group email set", func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()

		apiClient, _ := apiclient.NewMockClient(t)
		reconcilers, err := google_cdn_reconciler.New(ctx, serviceAccountEmail, managementProjectID, tenantName, workloadIdentityPoolName, google_cdn_reconciler.WithGcpServices(&google_cdn_reconciler.Services{}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconcilers.Reconcile(ctx, apiClient, naisTeamWithoutGoogleGroupEmail, log); !strings.Contains(err.Error(), "team slug has no google group email") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("return early if the team has no authorized repositories", func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()

		apiClient, mockServer := apiclient.NewMockClient(t)

		mockServer.Teams.EXPECT().
			ListAuthorizedRepositories(mock.Anything, &protoapi.ListAuthorizedRepositoriesRequest{TeamSlug: teamSlug}).
			Return(&protoapi.ListAuthorizedRepositoriesResponse{GithubRepositories: make([]string, 0)}, nil).
			Once()

		reconcilers, err := google_cdn_reconciler.New(ctx, serviceAccountEmail, managementProjectID, tenantName, workloadIdentityPoolName, google_cdn_reconciler.WithGcpServices(&google_cdn_reconciler.Services{}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = reconcilers.Reconcile(ctx, apiClient, naisTeam, log)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		mockServer.Teams.AssertNumberOfCalls(t, "ListAuthorizedRepositories", 1)
	})

	t.Run("full reconcile, no existing resources", func(t *testing.T) {
		log := logrus.StandardLogger()
		apiClient, mockServer := apiclient.NewMockClient(t)

		mockServer.Teams.EXPECT().
			ListAuthorizedRepositories(mock.Anything, &protoapi.ListAuthorizedRepositoriesRequest{TeamSlug: teamSlug}).
			Return(&protoapi.ListAuthorizedRepositoriesResponse{GithubRepositories: []string{"some-org/some-repository"}}, nil).
			Twice()

		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(req *protoapi.CreateAuditLogsRequest) bool {
				return req.ReconcilerName == "google:gcp:cdn" && req.Action == "cdn:provision-resources"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		mocks := mocks{
			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get service account that doesn't exist yet
				func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				},

				// create service account
				func(w http.ResponseWriter, r *http.Request) {
					var req iam.CreateServiceAccountRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					if req.ServiceAccount.Description != expectedServiceAccount.Description {
						t.Errorf("expected description %q, got %q", expectedServiceAccount.Description, req.ServiceAccount.Description)
					}

					if req.ServiceAccount.DisplayName != expectedServiceAccount.DisplayName {
						t.Errorf("expected display name %q, got %q", expectedServiceAccount.DisplayName, req.ServiceAccount.DisplayName)
					}

					if err := json.NewEncoder(w).Encode(expectedServiceAccount); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// set iam policy for service account
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&iam.Policy{}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
			}),
			storage: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get bucket attributes for non-existing bucket
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)

					if err := json.NewEncoder(w).Encode(&googleapi.Error{
						Code: http.StatusNotFound,
					}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// create bucket
				func(w http.ResponseWriter, r *http.Request) {
					var req storageold.Bucket
					_ = json.NewDecoder(r.Body).Decode(&req)

					if req.IamConfiguration == nil || req.IamConfiguration.UniformBucketLevelAccess == nil || !req.IamConfiguration.UniformBucketLevelAccess.Enabled {
						t.Errorf("expected uniform bucket level access to be enabled")
					}

					if req.Location != "europe-north1" {
						t.Errorf("expected location to be EU, got %q", req.Location)
					}

					// expected labels
					for key, val := range map[string]string{
						"team":       teamSlug,
						"tenant":     tenantName,
						"managed-by": "api-reconcilers",
					} {
						if req.Labels[key] != val {
							t.Errorf("expected label %q to be %q, got %q", key, val, req.Labels[key])
						}
					}

					// expected cors settings
					expectedCors := storage.CORS{
						MaxAge:          time.Hour,
						Methods:         []string{"GET"},
						Origins:         []string{"*"},
						ResponseHeaders: []string{"Content-Type"},
					}
					if len(req.Cors) < 1 {
						t.Fatalf("expected at least one cors config, got none")
					}

					actualCors := req.Cors[0]
					if time.Duration(actualCors.MaxAgeSeconds)*time.Second != expectedCors.MaxAge {
						t.Errorf("expected max age %v, got %v", expectedCors.MaxAge, req.Cors[0])
					}
					if !slices.Equal(actualCors.Method, expectedCors.Methods) {
						t.Errorf("expected methods %v, got %v", expectedCors.Methods, actualCors.Method)
					}
					if !slices.Equal(actualCors.Origin, expectedCors.Origins) {
						t.Errorf("expected origins %v, got %v", expectedCors.Origins, actualCors.Origin)
					}
					if !slices.Equal(actualCors.ResponseHeader, expectedCors.ResponseHeaders) {
						t.Errorf("expected response headers %v, got %v", expectedCors.ResponseHeaders, actualCors.ResponseHeader)
					}
					if err := json.NewEncoder(w).Encode(req); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// get bucket iam policy
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&storageold.Policy{}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// set bucket iam policy
				func(w http.ResponseWriter, r *http.Request) {
					var req storageold.Policy
					_ = json.NewDecoder(r.Body).Decode(&req)

					expectedPolicy := storageold.Policy{
						Bindings: []*storageold.PolicyBindings{
							{
								Members: []string{"allUsers"},
								Role:    "roles/storage.objectViewer",
							},
							{
								Members: []string{
									fmt.Sprintf("group:%s", googleGroupEmail),
									fmt.Sprintf("serviceAccount:%s", email),
								},
								Role: "roles/storage.objectAdmin",
							},
						},
					}

					if !slices.EqualFunc(req.Bindings, expectedPolicy.Bindings, func(a, b *storageold.PolicyBindings) bool {
						return a != nil && b != nil && a.Role == b.Role && slices.Equal(a.Members, b.Members)
					}) {
						t.Errorf("expected bindings %v, got %v", len(expectedPolicy.Bindings), len(req.Bindings))
					}

					if err := json.NewEncoder(w).Encode(&req); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
			}),
			backendbucket: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// look for existing backend bucket
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)

					if err := json.NewEncoder(w).Encode(&googleapi.Error{
						Code: http.StatusNotFound,
					}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// insert backend bucket
				func(w http.ResponseWriter, r *http.Request) {
					var req computepb.BackendBucket
					_ = json.NewDecoder(r.Body).Decode(&req)

					if err := json.NewEncoder(w).Encode(&computepb.Operation{}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// poll for status
				func(w http.ResponseWriter, r *http.Request) {
					var req computepb.BackendBucket
					_ = json.NewDecoder(r.Body).Decode(&req)

					if err := json.NewEncoder(w).Encode(&computepb.Operation{
						Status: ptr.To(computepb.Operation_DONE),
					}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// get created backend bucket
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&computepb.BackendBucket{
						Name:     ptr.To("some-backend-bucket"),
						SelfLink: ptr.To("self/link/some-backend-bucket"),
					}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
			}),
			project: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get iam policy for project
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&cloudresourcemanager.Policy{}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// set iam policy for project
				func(w http.ResponseWriter, r *http.Request) {
					expected := `{"policy":{"bindings":[{"members":["group:slug@example.com","serviceAccount:slug@management-project-123.iam.gserviceaccount.com"],"role":"projects/management-project-123/roles/cdnCacheInvalidator"}]}}`

					body, err := io.ReadAll(r.Body)
					defer r.Body.Close()
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if strings.TrimSpace(string(body)) != expected {
						t.Errorf("expected %q, got %q", expected, string(body))
					}

					w.Write(body)
				},
			}),
			urlMap: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get url map
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&compute.UrlMap{
						PathMatchers: []*compute.PathMatcher{
							{
								DefaultService: "some-default-service",
							},
						},
					}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// patch url map
				func(w http.ResponseWriter, r *http.Request) {
					expected := `{"pathMatchers":[{"defaultService":"some-default-service","pathRules":[{"paths":["/slug/*"],"service":"self/link/some-backend-bucket"}]}]}`

					body, err := io.ReadAll(r.Body)
					defer r.Body.Close()
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if strings.TrimSpace(string(body)) != expected {
						t.Errorf("expected %q, got %q", expected, string(body))
					}

					w.Write(body)
				},
			}),
		}
		services := mocks.start(t, ctx)
		reconciler, err := google_cdn_reconciler.New(ctx, serviceAccountEmail, managementProjectID, tenantName, workloadIdentityPoolName, google_cdn_reconciler.WithGcpServices(services))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = reconciler.Reconcile(ctx, apiClient, naisTeam, log)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestDelete(t *testing.T) {
	email := fmt.Sprintf("%s@%s.iam.gserviceaccount.com", teamSlug, managementProjectID)
	expectedServiceAccount := &iam.ServiceAccount{
		Email:       email,
		Name:        fmt.Sprintf("projects/%s/serviceAccounts/%s", managementProjectID, email),
		Description: fmt.Sprintf("service account for uploading to cdn buckets and cache invalidation for %s", teamSlug),
		DisplayName: fmt.Sprintf("CDN uploader for %s", teamSlug),
	}
	t.Run("Deletion calls the right endpoints in the right order", func(t *testing.T) {
		log := logrus.StandardLogger()

		apiClient, mockServer := apiclient.NewMockClient(t)

		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(req *protoapi.CreateAuditLogsRequest) bool {
				return req.ReconcilerName == "google:gcp:cdn" && req.Action == "cdn:delete-resources"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		mocks := mocks{
			backendbucket: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// look for existing backend bucket
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&computepb.BackendBucket{
						Name:     ptr.To("some-backend-bucket"),
						SelfLink: ptr.To("self/link/some-backend-bucket"),
					}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// delete backend bucket
				func(w http.ResponseWriter, r *http.Request) {
					var req computepb.BackendBucket
					_ = json.NewDecoder(r.Body).Decode(&req)

					if err := json.NewEncoder(w).Encode(&computepb.Operation{}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
			}),

			iam: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get service account
				func(w http.ResponseWriter, _ *http.Request) {
					if err := json.NewEncoder(w).Encode(expectedServiceAccount); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// delete service account call
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					if err := json.NewEncoder(w).Encode(&iam.ServiceAccount{}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},
			}),
			storage: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get the bucket attrs for the bucket that should get deleted
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&storageold.Bucket{}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// create bucket
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				},
			}),

			project: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get iam policy for project
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&cloudresourcemanager.Policy{
						Bindings: []*cloudresourcemanager.Binding{
							{
								Members: []string{"group:slug@example.com", "serviceAccount:slug@management-project-123.iam.gserviceaccount.com"},
								Role:    "projects/management-project-123/roles/cdnCacheInvalidator",
							},
						},
					}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// set iam policy for project
				func(w http.ResponseWriter, r *http.Request) {
					expected := `{"policy":{"bindings":[{"role":"projects/management-project-123/roles/cdnCacheInvalidator"}]}}`

					body, err := io.ReadAll(r.Body)
					defer r.Body.Close()
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if strings.TrimSpace(string(body)) != expected {
						t.Errorf("expected %q, got %q", expected, string(body))
					}

					w.Write(body)
				},
			}),
			urlMap: test.HttpServerWithHandlers(t, []http.HandlerFunc{
				// get url map
				func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewEncoder(w).Encode(&compute.UrlMap{
						PathMatchers: []*compute.PathMatcher{
							{
								DefaultService: "some-default-service",
								PathRules: []*compute.PathRule{
									{
										Paths:   []string{"/slug/*"},
										Service: "self/link/some-backend-bucket",
									}, {
										Paths:   []string{"/second-slug/*"},
										Service: "self/link/some-other-backend-bucket",
									},
								},
							},
						},
					}); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				},

				// patch url map
				func(w http.ResponseWriter, r *http.Request) {
					expected := `{"pathMatchers":[{"defaultService":"some-default-service","pathRules":[{"paths":["/second-slug/*"],"service":"self/link/some-other-backend-bucket"}]}]}`
					body, err := io.ReadAll(r.Body)
					defer r.Body.Close()
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if strings.TrimSpace(string(body)) != expected {
						t.Errorf("expected %q, got %q", expected, string(body))
					}

					w.Write(body)
				},
			}),
		}
		reconcilers, err := google_cdn_reconciler.New(
			ctx,
			serviceAccountEmail,
			managementProjectID,
			tenantName,
			workloadIdentityPoolName,
			google_cdn_reconciler.WithGcpServices(mocks.start(t, ctx)),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = reconcilers.Delete(ctx, apiClient, naisTeam, log)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
