package google_cdn_reconciler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	cloudcompute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"cloud.google.com/go/storage"
	"github.com/nais/api-reconcilers/internal/gcp"
	"github.com/nais/api-reconcilers/internal/google_token_source"
	github_team_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/github/team"
	gcpReconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/gcp"
	str "github.com/nais/api-reconcilers/internal/strings"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"k8s.io/utils/ptr"
)

const (
	managedByLabelName  = "managed-by"
	managedByLabelValue = "api-reconcilers"
	reconcilerName      = "google:gcp:cdn"
)

type services struct {
	backendBuckets                 *cloudcompute.BackendBucketsClient
	cloudResourceManagerOperations *cloudresourcemanager.OperationsService
	cloudResourceManagerProjects   *cloudresourcemanager.ProjectsService
	iam                            *iam.Service
	storage                        *storage.Client
	urlMap                         *compute.UrlMapsService
}
type cdnReconciler struct {
	googleManagementProjectID string
	services                  *services
	tenantName                string
	workloadIdentityPoolName  string
}

func (r *cdnReconciler) Name() string {
	return reconcilerName
}

func New(ctx context.Context, googleManagementProjectID, tenantDomain, tenantName string, workloadIdentityPoolName string) (*cdnReconciler, error) {
	r := &cdnReconciler{
		googleManagementProjectID: googleManagementProjectID,
		tenantName:                tenantName,
		services:                  nil,
		workloadIdentityPoolName:  workloadIdentityPoolName,
	}

	gcpServices, err := createGcpServices(ctx, googleManagementProjectID, tenantDomain)
	if err != nil {
		return nil, err
	}
	r.services = gcpServices

	return r, nil
}

// TODO: this does a lot of things that are not idempotent and we should probably have some kind of pattern for that in the reconciler(s)

func (r *cdnReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	labels := map[string]string{
		"team":             naisTeam.Slug,
		"tenant":           r.tenantName,
		managedByLabelName: managedByLabelValue,
	}

	if naisTeam.GoogleGroupEmail == nil {
		return fmt.Errorf("team %s has no google group email", naisTeam.Slug)
	}

	email := *naisTeam.GoogleGroupEmail

	urlMapName := "nais-cdn-urlmap"
	cacheInvalidatorRole := "roles/cdnCacheInvalidator"

	// bucket name needs to be globally unique
	tenantTeamName := fmt.Sprintf("%s-%s", strings.ReplaceAll(r.tenantName, ".", "-"), naisTeam.Slug)
	bucketName := str.SlugHashPrefixTruncate(tenantTeamName, "nais-cdn", gcp.StorageBucketNameMaxLength)

	googleServiceAccount, err := r.getOrCreateServiceAccount(ctx, naisTeam.Slug)
	if err != nil {
		return fmt.Errorf("get or create service account: %w", err)
	}

	err = r.setServiceAccountPolicy(ctx, googleServiceAccount, naisTeam.Slug, client)
	if err != nil {
		return fmt.Errorf("set service account policy: %w", err)
	}

	err = r.createBucketIfNotExists(ctx, bucketName, labels)
	if err != nil {
		return err
	}

	// set up iam policy for the bucket
	err = r.setBucketPolicy(ctx, bucketName, email, googleServiceAccount)
	if err != nil {
		return err
	}

	//  backend bucket
	backendBucket, err := r.getOrCreateBackendBucket(ctx, naisTeam, bucketName)
	if err != nil {
		return fmt.Errorf("get or create backend bucket: %w", err)
	}

	err = r.cacheInvalidationTeamAccess(ctx, email, googleServiceAccount, cacheInvalidatorRole)
	if err != nil {
		return fmt.Errorf("create team access for cache invalidation: %w", err)
	}

	err = r.createUrlMapIfNotExists(urlMapName, naisTeam, backendBucket)
	if err != nil {
		return fmt.Errorf("create urlMap: %w", err)
	}

	return nil
}

func (r *cdnReconciler) cacheInvalidationTeamAccess(ctx context.Context, email string, googleServiceAccount *iam.ServiceAccount, cacheInvalidatorRole string) error {
	// grant teams access to cache invalidation
	managementProjectName := "projects/" + r.googleManagementProjectID
	projectPolicy, err := r.services.cloudResourceManagerProjects.GetIamPolicy(managementProjectName, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("retrieve existing GCP project IAM policy: %w", err)
	}
	newBindings, updated := gcpReconciler.CalculateRoleBindings(projectPolicy.Bindings, map[string][]string{
		cacheInvalidatorRole: {
			fmt.Sprintf("group:%s", email),
			fmt.Sprintf("serviceAccount:%s", googleServiceAccount.Email),
		},
	})

	if updated {
		projectPolicy.Bindings = newBindings
		_, err = r.services.cloudResourceManagerProjects.SetIamPolicy(managementProjectName, &cloudresourcemanager.SetIamPolicyRequest{
			Policy: projectPolicy,
		}).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("assign GCP project IAM policy: %w", err)
		}
	}
	return nil
}

func (r *cdnReconciler) createUrlMapIfNotExists(urlMapName string, naisTeam *protoapi.Team, backendBucket *computepb.BackendBucket) error {
	// update urlMap in management project
	urlMap, err := r.services.urlMap.Get(r.googleManagementProjectID, urlMapName).Do()
	if err != nil {
		return fmt.Errorf("get urlmap: %w", err)
	}
	updatedUrlMap := false
	for _, pm := range urlMap.PathMatchers {
		seen := make(map[string]bool)
		for _, pr := range pm.PathRules {
			if !seen[pr.Service] {
				seen[pr.Service] = true
			}
		}
		pr := compute.PathRule{
			Paths:   []string{fmt.Sprintf("/%s/*", naisTeam.Slug)},
			Service: *backendBucket.SelfLink,
		}

		if !seen[*backendBucket.SelfLink] {
			pm.PathRules = append(pm.PathRules, &pr)
			updatedUrlMap = true
		}
	}

	if updatedUrlMap {
		_, err := r.services.urlMap.Update(r.googleManagementProjectID, urlMapName, urlMap).Do()
		if err != nil {
			return fmt.Errorf("update urlMap: %w", err)
		}
	}
	return nil
}

func (r *cdnReconciler) setBucketPolicy(ctx context.Context, bucketName string, email string, googleServiceAccount *iam.ServiceAccount) error {
	policy, err := r.services.storage.Bucket(bucketName).IAM().Policy(ctx)
	if err != nil {
		return fmt.Errorf("get bucket policy: %w", err)
	}
	policy.Add("allUsers", "roles/storage.objectViewer")
	policy.Add(fmt.Sprintf("group:%s", email), "roles/storage.objectAdmin")
	policy.Add(fmt.Sprintf("serviceAccount:%s", googleServiceAccount.Email), "roles/storage.objectAdmin")

	err = r.services.storage.Bucket(bucketName).IAM().SetPolicy(ctx, policy)
	if err != nil {
		return fmt.Errorf("add object viewer role to allUsers: %w", err)
	}
	return nil
}

func (r *cdnReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	// reverse order of creation

	// bucket name needs to be globally unique
	tenantTeamName := fmt.Sprintf("%s-%s", strings.ReplaceAll(r.tenantName, ".", "-"), naisTeam.Slug)
	bucketName := str.SlugHashPrefixTruncate(tenantTeamName, "nais-cdn", gcp.StorageBucketNameMaxLength)

	// TODO:
	//  remove from urlmap
	//  remove access to cache invalidation

	// remove backendbucket
	needsBackendBucket := false
	_, err := r.services.backendBuckets.Get(ctx, &computepb.GetBackendBucketRequest{
		BackendBucket: bucketName,
		Project:       r.googleManagementProjectID,
	})
	if err != nil {
		var gapiError *googleapi.Error

		if errors.As(err, &gapiError) {
			// retry transient errors
			if gapiError.Code != http.StatusNotFound {
				return err
			}
			// otherwise, we need a bucket i guess
			needsBackendBucket = true
		}
		return err
	}

	if !needsBackendBucket {
		_, err = r.services.backendBuckets.Delete(ctx, &computepb.DeleteBackendBucketRequest{
			BackendBucket: bucketName,
			Project:       r.googleManagementProjectID,
		})
		if err != nil {
			return fmt.Errorf("delete backend bucket: %w", err)
		}
	}

	// remove bucket
	_, err = r.services.storage.Bucket(bucketName).Attrs(ctx)
	if err != nil && errors.Is(err, storage.ErrBucketNotExist) {
		err = r.services.storage.Bucket(bucketName).Delete(ctx)
		if err != nil {
			return fmt.Errorf("delete bucket: %w", err)
		}
	}

	// remove service account
	serviceAccountName, _ := serviceAccountNameAndAccountID(naisTeam.Slug, r.googleManagementProjectID)
	_, err = r.services.iam.Projects.ServiceAccounts.Get(serviceAccountName).Context(ctx).Do()
	if err == nil {
		_, err = r.services.iam.Projects.ServiceAccounts.Delete(serviceAccountName).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("delete service account: %w", err)
		}
	}

	return nil
}

func (r *cdnReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "Google CDN",
		Description: "Provision CDN resources for team",
		MemberAware: false,
	}
}

// createGcpServices Creates the GCP services used by the reconciler
func createGcpServices(ctx context.Context, googleManagementProjectID, tenantDomain string) (*services, error) {
	builder, err := google_token_source.New(googleManagementProjectID, tenantDomain)
	if err != nil {
		return nil, err
	}
	ts, err := builder.GCP(ctx)
	if err != nil {
		return nil, fmt.Errorf("get delegated token source: %w", err)
	}

	opts := []option.ClientOption{
		option.WithTokenSource(ts),
	}

	cloudResourceManagerService, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve cloud resource manager service: %w", err)
	}

	computeService, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve compute service: %w", err)
	}

	iamService, err := iam.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve IAM service service: %w", err)
	}

	storageClient, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve storage client: %w", err)
	}

	backendBucketsClient, err := cloudcompute.NewBackendBucketsRESTClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve backend buckets client: %w", err)
	}

	return &services{
		iam:                            iamService,
		backendBuckets:                 backendBucketsClient,
		cloudResourceManagerOperations: cloudResourceManagerService.Operations,
		cloudResourceManagerProjects:   cloudResourceManagerService.Projects,
		storage:                        storageClient,
		urlMap:                         computeService.UrlMaps,
	}, nil
}

func (r *cdnReconciler) getOrCreateServiceAccount(ctx context.Context, teamSlug string) (*iam.ServiceAccount, error) {
	serviceAccountName, accountID := serviceAccountNameAndAccountID(teamSlug, r.googleManagementProjectID)

	existing, err := r.services.iam.Projects.ServiceAccounts.Get(serviceAccountName).Context(ctx).Do()
	if err == nil {
		return existing, nil
	}

	return r.services.iam.Projects.ServiceAccounts.Create("projects/"+r.googleManagementProjectID, &iam.CreateServiceAccountRequest{
		AccountId: accountID,
		ServiceAccount: &iam.ServiceAccount{
			Description: fmt.Sprintf("service account for uploading to cdn buckets and cache invalidation for %s", teamSlug),
			DisplayName: fmt.Sprintf("CDN uploader for %s", teamSlug),
		},
	}).Context(ctx).Do()
}

func (r *cdnReconciler) createBucketIfNotExists(ctx context.Context, bucketName string, labels map[string]string) error {
	_, err := r.services.storage.Bucket(bucketName).Attrs(ctx)
	if err != nil && !errors.Is(err, storage.ErrBucketNotExist) {
		return fmt.Errorf("get bucket: %w", err)
	}

	if errors.Is(err, storage.ErrBucketNotExist) {
		// set up a storage bucket
		err = r.services.storage.Bucket(bucketName).Create(ctx, r.googleManagementProjectID, &storage.BucketAttrs{Labels: labels})
		if err != nil {
			return fmt.Errorf("create bucket: %w", err)
		}
	}

	return nil
}

func (r *cdnReconciler) getOrCreateBackendBucket(ctx context.Context, naisTeam *protoapi.Team, bucketName string) (*computepb.BackendBucket, error) {
	needsBackendBucket := false
	backendBucket, err := r.services.backendBuckets.Get(ctx, &computepb.GetBackendBucketRequest{
		BackendBucket: bucketName,
		Project:       r.googleManagementProjectID,
	})
	// 👇 this is very not good my guy
	if err != nil {
		var gapiError *googleapi.Error

		if errors.As(err, &gapiError) {
			// retry transient errors
			if gapiError.Code != http.StatusNotFound {
				return nil, err
			}
			// otherwise, we need a bucket i guess
			needsBackendBucket = true
		}
		return nil, err
	}

	// set up a backend bucket
	if needsBackendBucket {
		// TODO: for feature parity, these should be configurable for each team, to be received from somewhere.
		const defaultTTL = int32(3600)
		const defaultMaxTTL = int32(86400) // TODO: previously max(config, 86400),

		req := &computepb.InsertBackendBucketRequest{
			BackendBucketResource: &computepb.BackendBucket{
				BucketName: &bucketName,
				CdnPolicy: &computepb.BackendBucketCdnPolicy{
					// Enables Cloud CDN to cache all static content served from the backend
					// bucket. This includes content with a file extension that is typically
					// associated with static content, such as .html, .css, and .js.
					CacheMode:  ptr.To("CACHE_ALL_STATIC"),
					ClientTtl:  ptr.To(defaultTTL),
					DefaultTtl: ptr.To(defaultTTL),
					MaxTtl:     ptr.To(defaultMaxTTL),
					// If true then Cloud CDN will combine multiple concurrent cache fill
					// requests into a small number of requests to the origin.
					RequestCoalescing: ptr.To(true),
				},
				// When enabled, Cloud CDN automatically compresses content served from the
				// backend bucket using gzip compression. This can reduce the amount of data
				// sent over the network, resulting in faster load times for end users.
				// Enum of "AUTOMATIC", "DISABLED".
				CompressionMode: ptr.To("AUTOMATIC"),
				Description:     ptr.To(fmt.Sprintf("Backend bucket for %s", naisTeam.Slug)),
				EnableCdn:       ptr.To(true),
				Name:            &bucketName,
			},
			Project: r.googleManagementProjectID,
		}

		backendBucketInsertion, err := r.services.backendBuckets.Insert(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("insert backend bucket: %w", err)
		}

		err = backendBucketInsertion.Wait(ctx)
		if err != nil {
			return nil, fmt.Errorf("wait for insert backend bucket operation: %w", err)
		}

		backendBucket, err = r.services.backendBuckets.Get(ctx, &computepb.GetBackendBucketRequest{
			BackendBucket: bucketName,
			Project:       r.googleManagementProjectID,
		})
		if err != nil {
			return backendBucket, fmt.Errorf("get backend bucket: %w", err)
		}
	}
	return backendBucket, nil
}

func serviceAccountNameAndAccountID(teamSlug, projectID string) (serviceAccountName, accountID string) {
	accountID = str.SlugHashPrefixTruncate(teamSlug, "cdn", gcp.GoogleServiceAccountMaxLength)
	emailAddress := fmt.Sprintf("%s@%s.iam.gserviceaccount.com", accountID, projectID)
	serviceAccountName = fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, emailAddress)
	return
}

func (r *cdnReconciler) setServiceAccountPolicy(ctx context.Context, serviceAccount *iam.ServiceAccount, teamSlug string, client *apiclient.APIClient) error {
	members, err := r.getServiceAccountPolicyMembers(ctx, teamSlug, client)
	if err != nil {
		return err
	}

	req := iam.SetIamPolicyRequest{
		Policy: &iam.Policy{
			Bindings: []*iam.Binding{
				{
					Members: members,
					Role:    "roles/iam.workloadIdentityUser",
				},
			},
		},
	}

	_, err = r.services.iam.Projects.ServiceAccounts.SetIamPolicy(serviceAccount.Name, &req).Context(ctx).Do()
	return err
}

func (r *cdnReconciler) getServiceAccountPolicyMembers(ctx context.Context, teamSlug string, client *apiclient.APIClient) ([]string, error) {
	repos, err := github_team_reconciler.GetTeamRepositories(ctx, client.Reconcilers(), teamSlug)
	if err != nil {
		return nil, err
	}

	members := make([]string, 0)
	for _, githubRepo := range repos {
		if githubRepo.Archived {
			continue
		}

		// TODO: this should only be for authorized repositories, get from api
		for _, perm := range githubRepo.Permissions {
			if perm.Name == "push" && perm.Granted {
				member := "principalSet://iam.googleapis.com/" + r.workloadIdentityPoolName + "/attribute.repository/" + githubRepo.Name
				members = append(members, member)
				break
			}
		}
	}

	return members, nil
}
