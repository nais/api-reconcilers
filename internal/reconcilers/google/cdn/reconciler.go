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
	gcpReconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/gcp"
	str "github.com/nais/api-reconcilers/internal/strings"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"k8s.io/utils/ptr"

	"github.com/nais/api-reconcilers/internal/google_token_source"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"google.golang.org/api/option"
)

const (
	reconcilerName      = "google:gcp:cdn"
	managedByLabelName  = "managed-by"
	managedByLabelValue = "api-reconcilers"
)

type services struct {
	iam                            *iam.Service
	backendBuckets                 *cloudcompute.BackendBucketsClient
	cloudResourceManagerProjects   *cloudresourcemanager.ProjectsService
	cloudResourceManagerOperations *cloudresourcemanager.OperationsService
	storage                        *storage.Client
	urlMap                         *compute.UrlMapsService
}
type cdnReconciler struct {
	googleManagementProjectID string
	tenantName                string
	services                  *services
}

func (r *cdnReconciler) Name() string {
	return reconcilerName
}

func New(ctx context.Context, googleManagementProjectID, tenantDomain, tenantName string) (*cdnReconciler, error) {
	r := &cdnReconciler{
		googleManagementProjectID: googleManagementProjectID,
		tenantName:                tenantName,
		services:                  nil,
	}

	gcpServices, err := createGcpServices(ctx, googleManagementProjectID, tenantDomain)
	if err != nil {
		return nil, err
	}
	r.services = gcpServices

	return r, nil
}

// TODO: this does a lot of things that are not idempotent and we should probably have some kind of pattern for that in the reconciler(s)
// TODO: federation/workload identity setup for each team
// TODO: buckets must be in the same project as the backend bucket (and all other cdn thingies)
// TODO: add labels for all resources that we create

func (r *cdnReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	// TODO
	// resource "google_service_account" "github" {
	//   for_each = var.teams

	//   display_name = "github-${each.key}-bucket-writer"
	//   description  = "Service account for ${each.key} team to write to GCS bucket"
	//   account_id   = "gh-${each.key}"
	// }

	// resource "google_storage_bucket_iam_member" "github" {
	//   for_each = var.teams

	//   bucket = google_storage_bucket.teams[each.key].name
	//   role   = "roles/storage.objectAdmin"
	//   member = "serviceAccount:${google_service_account.github[each.key].email}"
	// }

	// resource "google_service_account_iam_member" "github" {
	//   for_each = local.repo-map

	//   service_account_id = google_service_account.github[each.value.team].id
	//   role               = "roles/iam.workloadIdentityUser"
	//   member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.pool.name}/attribute.repository/${each.value.repo}"
	// }

	// resource "google_project_iam_member" "github_cache_invalidator" {
	//   for_each = var.teams

	//   project = var.project
	//   role    = google_project_iam_custom_role.team_cache_invalidator.name
	//   member  = "serviceAccount:${google_service_account.github[each.key].email}"
	// }

	labels := map[string]string{
		"team":             naisTeam.Slug,
		"tenant":           r.tenantName,
		managedByLabelName: managedByLabelValue,
	}

	urlMapName := "nais-cdn-urlmap"
	cacheInvalidatorRole := "roles/cdnCacheInvalidator"

	// bucket name needs to be globally unique
	tenantTeamName := fmt.Sprintf("%s-%s", strings.ReplaceAll(r.tenantName, ".", "-"), naisTeam.Slug)
	bucketName := str.SlugHashPrefixTruncate(tenantTeamName, "nais-cdn", gcp.StorageBucketNameMaxLength)

	// check for existence for early return
	_, err := r.services.storage.Bucket(bucketName).Attrs(ctx)
	if err != nil && errors.Is(err, storage.ErrBucketNotExist) {
		log.Infof("bucket %q already exists, skipping cdn setup", bucketName)
		return nil
	}

	// set up a storage bucket
	err = r.services.storage.Bucket(bucketName).Create(ctx, r.googleManagementProjectID, &storage.BucketAttrs{Labels: labels})
	if err != nil {
		return fmt.Errorf("create bucket: %w", err)
	}

	// set up iam policy for the bucket
	policy, err := r.services.storage.Bucket(bucketName).IAM().Policy(ctx)
	if err != nil {
		return fmt.Errorf("get bucket policy: %w", err)
	}
	policy.Add("allUsers", "roles/storage.objectViewer")
	policy.Add(fmt.Sprintf("group:%s", naisTeam.GoogleGroupEmail), "roles/storage.objectAdmin")

	err = r.services.storage.Bucket(bucketName).IAM().SetPolicy(ctx, policy)
	if err != nil {
		return fmt.Errorf("add object viewer role to allUsers: %w", err)
	}

	// check for existing backend bucket
	needsBackendBucket := false
	backendBucket, err := r.services.backendBuckets.Get(ctx, &computepb.GetBackendBucketRequest{
		BackendBucket: bucketName,
		Project:       r.googleManagementProjectID,
	})
	// TODO: this is very not good my guy
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
		// if it's not a google api error, shit's fucked
		return err
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
			return fmt.Errorf("insert backend bucket: %w", err)
		}

		err = backendBucketInsertion.Wait(ctx)
		if err != nil {
			return fmt.Errorf("wait for insert backend bucket operation: %w", err)
		}

		backendBucket, err = r.services.backendBuckets.Get(ctx, &computepb.GetBackendBucketRequest{
			BackendBucket: bucketName,
			Project:       r.googleManagementProjectID,
		})
		if err != nil {
			return fmt.Errorf("get backend bucket: %w", err)
		}
	}

	// grant teams access to cache invalidation
	managementProjectName := "projects/" + r.googleManagementProjectID
	projectPolicy, err := r.services.cloudResourceManagerProjects.GetIamPolicy(managementProjectName, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("retrieve existing GCP project IAM policy: %w", err)
	}
	newBindings, updated := gcpReconciler.CalculateRoleBindings(projectPolicy.Bindings, map[string]string{
		cacheInvalidatorRole: "group:" + naisTeam.GoogleGroupEmail,
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

func (*cdnReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	// Todo: Delete??
	return nil
}

func (r *cdnReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "CDN reconciler",
		Description: "CDN",
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
		option.WithHTTPClient(otelhttp.DefaultClient),
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
