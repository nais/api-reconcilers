package google_cdn_reconciler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/nais/api-reconcilers/internal/reconcilers"

	cloudcompute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"cloud.google.com/go/storage"
	"github.com/nais/api-reconcilers/internal/gcp"
	"github.com/nais/api-reconcilers/internal/google_token_source"
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
	managedByLabelName    = "managed-by"
	managedByLabelValue   = "api-reconcilers"
	reconcilerName        = "google:gcp:cdn"
	urlMapName            = "nais-cdn"
	auditActionDeletedCdn = "cdn:provision-resources"
	auditActionCreatedCdn = "cdn:delete-resources"
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
	cacheReconcilerRoleID     string
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
	r.cacheReconcilerRoleID = fmt.Sprintf("projects/%s/roles/cdnCacheInvalidator", googleManagementProjectID)

	return r, nil
}

func (r *cdnReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "Google CDN",
		Description: "Provision CDN resources for team",
		MemberAware: false,
	}
}

func (r *cdnReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	if naisTeam.GoogleGroupEmail == nil {
		return fmt.Errorf("team %s has no google group email", naisTeam.Slug)
	}

	labels := map[string]string{
		"team":             naisTeam.Slug,
		"tenant":           r.tenantName,
		managedByLabelName: managedByLabelValue,
	}
	teamEmail := *naisTeam.GoogleGroupEmail

	// bucket name needs to be globally unique
	tenantTeamName := fmt.Sprintf("%s-%s", strings.ReplaceAll(r.tenantName, ".", "-"), naisTeam.Slug)
	bucketName := str.SlugHashPrefixTruncate(tenantTeamName, "nais-cdn", gcp.StorageBucketNameMaxLength)

	googleServiceAccount, err := r.getOrCreateServiceAccount(ctx, naisTeam.Slug)
	if err != nil {
		return fmt.Errorf("get or create service account: %w", err)
	}
	log.Infof("created service account %s", googleServiceAccount.Email)

	// ❌ TODO: re-enable whenever github team state is fixed
	err = r.setServiceAccountPolicy(ctx, googleServiceAccount, naisTeam.Slug, client)
	if err != nil {
		return fmt.Errorf("set service account policy: %w", err)
	}
	log.Infof("set service account policy for %s", googleServiceAccount.Email)

	err = r.createBucketIfNotExists(ctx, bucketName, labels)
	if err != nil {
		return fmt.Errorf("create bucket: %w", err)
	}
	log.Infof("created bucket %s", bucketName)

	// set up iam policy for the bucket
	err = r.setBucketPolicy(ctx, bucketName, teamEmail, googleServiceAccount)
	if err != nil {
		return fmt.Errorf("set bucket policy: %w", err)
	}
	log.Infof("set bucket policy for %s", bucketName)

	backendBucket, err := r.getOrCreateBackendBucket(ctx, naisTeam, bucketName)
	if err != nil {
		return fmt.Errorf("get or create backend bucket: %w", err)
	}
	log.Infof("got backend bucket %s", *backendBucket.Name)

	err = r.setCacheInvalidationIamPolicy(ctx, teamEmail, googleServiceAccount)
	if err != nil {
		return fmt.Errorf("create team access for cache invalidation: %w", err)
	}
	log.Infof("set cache invalidation IAM policy for %s", teamEmail)
	log.Infof("set cache invalidation IAM policy for %s", googleServiceAccount.Email)

	err = r.ensureUrlMapPathRule(naisTeam, backendBucket)
	if err != nil {
		return fmt.Errorf("create urlMap: %w", err)
	}
	log.Infof("added path rule for %s to url map", naisTeam.Slug)

	log.Infof("reconciled cdn for %s", naisTeam.Slug)

	reconcilers.AuditLogForTeam(
		ctx,
		client,
		r,
		auditActionCreatedCdn,
		naisTeam.Slug,
		"Provisioned CDN resources for %s", naisTeam.Slug,
	)
	return nil
}

func (r *cdnReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	// reverse order of creation

	// bucket name needs to be globally unique
	tenantTeamName := fmt.Sprintf("%s-%s", strings.ReplaceAll(r.tenantName, ".", "-"), naisTeam.Slug)
	bucketName := str.SlugHashPrefixTruncate(tenantTeamName, "nais-cdn", gcp.StorageBucketNameMaxLength)

	// get backendbucket
	backendBucket, err := r.services.backendBuckets.Get(ctx, &computepb.GetBackendBucketRequest{
		BackendBucket: bucketName,
		Project:       r.googleManagementProjectID,
	})
	if err != nil {
		return err
	}

	// remove entry from urlmap
	urlMap, err := r.services.urlMap.Get(r.googleManagementProjectID, urlMapName).Do()
	if err != nil {
		return fmt.Errorf("get urlmap: %w", err)
	}

	for _, pm := range urlMap.PathMatchers {
		seen := make(map[string]bool)
		for _, pr := range pm.PathRules {
			if !seen[pr.Service] {
				seen[pr.Service] = true
			}
		}

		pm.PathRules = slices.DeleteFunc(pm.PathRules, func(rule *compute.PathRule) bool {
			return rule.Service == *backendBucket.SelfLink
		})
	}

	_, err = r.services.urlMap.Update(r.googleManagementProjectID, urlMapName, urlMap).Do()
	if err != nil {
		return fmt.Errorf("update urlMap: %w", err)
	}
	log.Infof("removed path rule for %s from url map", naisTeam.Slug)

	// delete backendbucket
	if backendBucket != nil {
		_, err = r.services.backendBuckets.Delete(ctx, &computepb.DeleteBackendBucketRequest{
			BackendBucket: bucketName,
			Project:       r.googleManagementProjectID,
		})
		if err != nil {
			return fmt.Errorf("delete backend bucket: %w", err)
		}
		log.Infof("deleted backend bucket %s", *backendBucket.Name)
	}

	// remove bucket
	_, err = r.services.storage.Bucket(bucketName).Attrs(ctx)
	if err != nil && !errors.Is(err, storage.ErrBucketNotExist) {
		return fmt.Errorf("get bucket: %w", err)
	}

	if err == nil {
		err = r.services.storage.Bucket(bucketName).Delete(ctx)
		if err != nil {
			return fmt.Errorf("delete bucket: %w", err)
		}
		log.Infof("deleted bucket %s", bucketName)
	}

	// get iam policy for project
	managementProjectName := "projects/" + r.googleManagementProjectID
	projectPolicy, err := r.services.cloudResourceManagerProjects.GetIamPolicy(managementProjectName, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("retrieve existing GCP project IAM policy: %w", err)
	}

	// get existing service account
	serviceAccountName, _ := serviceAccountNameAndAccountID(naisTeam.Slug, r.googleManagementProjectID)
	serviceAccount, err := r.services.iam.Projects.ServiceAccounts.Get(serviceAccountName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("get service account: %w", err)
	}

	// remove access to cache invalidation
	for _, binding := range projectPolicy.Bindings {
		if binding.Role == r.cacheReconcilerRoleID {
			binding.Members = slices.DeleteFunc(binding.Members, func(member string) bool {
				return member == fmt.Sprintf("group:%s", *naisTeam.GoogleGroupEmail)
			})
			binding.Members = slices.DeleteFunc(binding.Members, func(member string) bool {
				return member == fmt.Sprintf("serviceAccount:%s", serviceAccount.Email)
			})
		}
	}

	_, err = r.services.cloudResourceManagerProjects.SetIamPolicy(managementProjectName, &cloudresourcemanager.SetIamPolicyRequest{
		Policy: projectPolicy,
	}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("assign GCP project IAM policy: %w", err)
	}
	log.Infof("removed cache invalidation IAM policy for %s", naisTeam.Slug)

	// delete service account
	_, err = r.services.iam.Projects.ServiceAccounts.Delete(serviceAccountName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("delete service account: %w", err)
	}
	log.Infof("deleted service account %s", serviceAccount.Email)

	log.Infof("deleted cdn resources for %s", naisTeam.Slug)

	reconcilers.AuditLogForTeam(
		ctx,
		client,
		r,
		auditActionDeletedCdn,
		naisTeam.Slug,
		"Deleted CDN resources for %s", naisTeam.Slug,
	)
	return nil
}

func (r *cdnReconciler) setCacheInvalidationIamPolicy(ctx context.Context, teamEmail string, googleServiceAccount *iam.ServiceAccount) error {
	// grant teams access to cache invalidation
	managementProjectName := "projects/" + r.googleManagementProjectID
	projectPolicy, err := r.services.cloudResourceManagerProjects.GetIamPolicy(managementProjectName, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("retrieve existing GCP project IAM policy: %w", err)
	}

	newBindings, updated := gcpReconciler.CalculateRoleBindings(projectPolicy.Bindings, map[string][]string{
		r.cacheReconcilerRoleID: {
			fmt.Sprintf("group:%s", teamEmail),
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

// ensureUrlMapPathRule ensures that the backend bucket exists for at least one path rule in the given urlMap
func (r *cdnReconciler) ensureUrlMapPathRule(naisTeam *protoapi.Team, backendBucket *computepb.BackendBucket) error {
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
		attrs := &storage.BucketAttrs{
			UniformBucketLevelAccess: storage.UniformBucketLevelAccess{Enabled: true},
			Location:                 "europe-north1",
			Labels:                   labels,
			CORS: []storage.CORS{
				{
					MaxAge:          time.Hour,
					Methods:         []string{"GET"},
					Origins:         []string{"*"},
					ResponseHeaders: []string{"Content-Type"},
				},
			},
		}

		err = r.services.storage.Bucket(bucketName).Create(ctx, r.googleManagementProjectID, attrs)
		if err != nil {
			return err
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
	if err != nil {
		var gapiError *googleapi.Error

		if errors.As(err, &gapiError) {
			// retry transient errors
			if gapiError.Code != http.StatusNotFound {
				return nil, fmt.Errorf("googleapi error: %w", err)
			}

			needsBackendBucket = true
		} else {
			return nil, fmt.Errorf("unknown error: %w", err)
		}
	}

	if !needsBackendBucket {
		return backendBucket, nil
	}

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
		return nil, fmt.Errorf("get created backend bucket: %w", err)
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
		return fmt.Errorf("get service account policy members: %w", err)
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
	resp, err := client.Teams().ListAuthorizedRepositories(ctx, &protoapi.ListAuthorizedRepositoriesRequest{TeamSlug: teamSlug})
	if err != nil {
		return nil,
			fmt.Errorf("get team repositories: %w", err)
	}

	members := make([]string, 0)
	for _, repo := range resp.GithubRepositories {
		members = append(members, "principalSet://iam.googleapis.com/"+r.workloadIdentityPoolName+"/attribute.repository/"+repo)
	}

	return members, nil
}
