package google_gar_reconciler

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	"cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/nais/api-reconcilers/internal/gcp"
	"github.com/nais/api-reconcilers/internal/google_token_source"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	str "github.com/nais/api-reconcilers/internal/strings"
)

const (
	reconcilerName = "google:gcp:gar"

	managedByLabelName  = "managed-by"
	managedByLabelValue = "api-reconcilers"

	auditActionCreateGarRepository = "google:gar:create"
	auditActionDeleteGarRepository = "google:gar:delete"
)

type garReconciler struct {
	googleManagementProjectID string
	workloadIdentityPoolName  string
	artifactRegistry          *artifactregistry.Client
	iamService                *iam.Service
}

type OptFunc func(*garReconciler)

func WithGarClient(client *artifactregistry.Client) OptFunc {
	return func(r *garReconciler) {
		r.artifactRegistry = client
	}
}

func WithIAMService(service *iam.Service) OptFunc {
	return func(r *garReconciler) {
		r.iamService = service
	}
}

func New(ctx context.Context, serviceAccountEmail, googleManagementProjectID, workloadIdentityPoolName string, opts ...OptFunc) (reconcilers.Reconciler, error) {
	r := &garReconciler{
		googleManagementProjectID: googleManagementProjectID,
		workloadIdentityPoolName:  workloadIdentityPoolName,
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.iamService == nil || r.artifactRegistry == nil {
		ts, err := google_token_source.GcpTokenSource(ctx, serviceAccountEmail)
		if err != nil {
			return nil, fmt.Errorf("get delegated token source: %w", err)
		}

		if r.iamService == nil {
			iamService, err := iam.NewService(ctx, option.WithTokenSource(ts))
			if err != nil {
				return nil, err
			}
			r.iamService = iamService
		}

		if r.artifactRegistry == nil {
			artifactRegistry, err := artifactregistry.NewClient(ctx, option.WithTokenSource(ts), option.WithGRPCDialOption(grpc.WithStatsHandler(otelgrpc.NewClientHandler())))
			if err != nil {
				return nil, err
			}
			r.artifactRegistry = artifactRegistry
		}
	}

	return r, nil
}

func (r *garReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "Google Artifact Registry",
		Description: "Provision artifact registry repositories for Console teams.",
		MemberAware: false,
	}
}

func (r *garReconciler) Name() string {
	return reconcilerName
}

func (r *garReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	log.Infof("started reconciling GAR for %q", naisTeam.Slug)

	serviceAccount, err := r.getOrCreateServiceAccount(ctx, naisTeam.Slug)
	if err != nil {
		return err
	}

	if err := r.setServiceAccountPolicy(ctx, serviceAccount, naisTeam.Slug, client); err != nil {
		return err
	}

	garRepository, err := r.getOrCreateOrUpdateGarRepository(ctx, naisTeam.Slug, log)
	if err != nil {
		return err
	}

	updated, err := r.setGarRepositoryPolicy(ctx, garRepository, serviceAccount, naisTeam.GoogleGroupEmail)
	if err != nil {
		return err
	}

	if updated {
		reconcilers.AuditLogForTeam(
			ctx,
			client,
			r,
			auditActionCreateGarRepository,
			naisTeam.Slug,
			"Updated repository policy for %q", *naisTeam.GarRepository)
	}

	_, err = client.Teams().SetTeamExternalReferences(ctx, &protoapi.SetTeamExternalReferencesRequest{
		Slug:          naisTeam.Slug,
		GarRepository: &garRepository.Name,
	})
	if err != nil {
		return err
	}

	log.Infof("finished reconciling GAR for %q", naisTeam.Slug)

	return nil
}

func (r *garReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	if naisTeam.GarRepository == nil {
		log.Warnf("missing repository name in team, assume team has already been deleted")
		return nil
	}

	serviceAccountName, _ := serviceAccountNameAndAccountID(naisTeam.Slug, r.googleManagementProjectID)
	if _, err := r.iamService.Projects.ServiceAccounts.Delete(serviceAccountName).Context(ctx).Do(); err != nil {
		googleError, ok := err.(*googleapi.Error)
		if !ok || googleError.Code != http.StatusNotFound {
			return fmt.Errorf("delete service account %q: %w", serviceAccountName, err)
		}

		log.WithError(err).Errorf("GAR service account %q does not exist, nothing to delete", serviceAccountName)
	}

	// Check if repository exists, if it doesn't, no need to delete it
	_, err := r.artifactRegistry.GetRepository(ctx, &artifactregistrypb.GetRepositoryRequest{Name: *naisTeam.GarRepository})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			return nil
		}
	}

	req := &artifactregistrypb.DeleteRepositoryRequest{
		Name: *naisTeam.GarRepository,
	}
	operation, err := r.artifactRegistry.DeleteRepository(ctx, req)
	if err != nil {
		return fmt.Errorf("delete GAR repository for team %q: %w", naisTeam.Slug, err)
	}

	if err = operation.Wait(ctx); err != nil {
		return fmt.Errorf("wait for GAR repository deletion for team %q: %w", naisTeam.Slug, err)
	}

	reconcilers.AuditLogForTeam(
		ctx,
		client,
		r,
		auditActionDeleteGarRepository,
		naisTeam.Slug,
		"Delete GAR repository %q", *naisTeam.GarRepository,
	)
	return err
}

func (r *garReconciler) getOrCreateServiceAccount(ctx context.Context, teamSlug string) (*iam.ServiceAccount, error) {
	serviceAccountName, accountID := serviceAccountNameAndAccountID(teamSlug, r.googleManagementProjectID)

	existing, err := r.iamService.Projects.ServiceAccounts.Get(serviceAccountName).Context(ctx).Do()
	if err == nil {
		return existing, nil
	}

	return r.iamService.Projects.ServiceAccounts.Create("projects/"+r.googleManagementProjectID, &iam.CreateServiceAccountRequest{
		AccountId: accountID,
		ServiceAccount: &iam.ServiceAccount{
			Description: "Service Account used to push images to Google Artifact Registry for " + teamSlug,
			DisplayName: "Artifact Pusher for " + teamSlug,
		},
	}).Context(ctx).Do()
}

func (r *garReconciler) setServiceAccountPolicy(ctx context.Context, serviceAccount *iam.ServiceAccount, teamSlug string, client *apiclient.APIClient) error {
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

	_, err = r.iamService.Projects.ServiceAccounts.SetIamPolicy(serviceAccount.Name, &req).Context(ctx).Do()
	return err
}

func (r *garReconciler) getOrCreateOrUpdateGarRepository(ctx context.Context, teamSlug string, log logrus.FieldLogger) (*artifactregistrypb.Repository, error) {
	parent := "projects/" + r.googleManagementProjectID + "/locations/europe-north1"
	name := parent + "/repositories/" + teamSlug
	description := fmt.Sprintf("Docker repository for team %q. Managed by github.com/nais/api-reconcilers.", teamSlug)

	getRequest := &artifactregistrypb.GetRepositoryRequest{
		Name: name,
	}
	existing, err := r.artifactRegistry.GetRepository(ctx, getRequest)
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}

	if existing == nil {
		template := &artifactregistrypb.Repository{
			Format:      artifactregistrypb.Repository_DOCKER,
			Name:        name,
			Description: description,
			Labels: map[string]string{
				"team":             teamSlug,
				managedByLabelName: managedByLabelValue,
			},
		}

		createRequest := &artifactregistrypb.CreateRepositoryRequest{
			Parent:       parent,
			Repository:   template,
			RepositoryId: teamSlug,
		}

		createResponse, err := r.artifactRegistry.CreateRepository(ctx, createRequest)
		if err != nil {
			return nil, err
		}

		return createResponse.Wait(ctx)
	}

	if existing.Format != artifactregistrypb.Repository_DOCKER {
		return nil, fmt.Errorf("existing repo has invalid format: %q %q", name, existing.Format)
	}

	return r.updateGarRepository(ctx, existing, teamSlug, description, log)
}

func (r *garReconciler) getServiceAccountPolicyMembers(ctx context.Context, teamSlug string, client *apiclient.APIClient) ([]string, error) {
	resp, err := client.Teams().ListAuthorizedRepositories(ctx, &protoapi.ListAuthorizedRepositoriesRequest{
		TeamSlug: teamSlug,
	})
	if err != nil {
		return []string{}, fmt.Errorf("get authorized team repositories: %w", err)
	}

	members := make([]string, 0)
	for _, githubRepo := range resp.GithubRepositories {
		member := "principalSet://iam.googleapis.com/" + r.workloadIdentityPoolName + "/attribute.repository/" + githubRepo
		members = append(members, member)
	}

	return members, nil
}

func (r *garReconciler) updateGarRepository(ctx context.Context, repository *artifactregistrypb.Repository, teamSlug, description string, log logrus.FieldLogger) (*artifactregistrypb.Repository, error) {
	var changes []string
	if repository.Labels["team"] != teamSlug {
		repository.Labels["team"] = teamSlug
		changes = append(changes, "labels.team")
	}

	if repository.Labels[managedByLabelName] != managedByLabelValue {
		repository.Labels[managedByLabelName] = managedByLabelValue
		changes = append(changes, "labels.managed-by")
	}

	if repository.Description != description {
		repository.Description = fmt.Sprintf("Docker repository for team %q. Managed by github.com/nais/api-reconcilers.", teamSlug)
		changes = append(changes, "description")
	}

	targetPolicies := DefaultCleanupPolicies()
	policyUpToDate := maps.EqualFunc(targetPolicies, repository.CleanupPolicies, func(a, b *artifactregistrypb.CleanupPolicy) bool {
		return proto.Equal(a, b)
	})

	if !policyUpToDate || repository.CleanupPolicyDryRun {
		repository.CleanupPolicyDryRun = false
		repository.CleanupPolicies = targetPolicies
		changes = append(changes, "cleanup_policies")
		changes = append(changes, "cleanup_policy_dry_run")
	}

	if len(changes) > 0 {
		updateRequest := &artifactregistrypb.UpdateRepositoryRequest{
			Repository: repository,
			UpdateMask: &fieldmaskpb.FieldMask{
				Paths: changes,
			},
		}

		return r.artifactRegistry.UpdateRepository(ctx, updateRequest)
	}

	log.Debugf("existing repository is up to date")
	return repository, nil
}

func (r *garReconciler) setGarRepositoryPolicy(ctx context.Context, repository *artifactregistrypb.Repository, serviceAccount *iam.ServiceAccount, groupEmail *string) (bool, error) {
	resp, err := r.artifactRegistry.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: repository.Name,
	})
	if err != nil {
		return false, err
	}

	bindings := []*iampb.Binding{
		{
			Role:    "roles/artifactregistry.writer",
			Members: []string{"serviceAccount:" + serviceAccount.Email},
		},
	}

	if groupEmail != nil {
		bindings = append(bindings, &iampb.Binding{
			Role:    "roles/artifactregistry.repoAdmin",
			Members: []string{"group:" + *groupEmail},
		})
	}

	if IsIAMPolicyBindingEqual(bindings, resp.Bindings) {
		return false, nil
	}

	_, err = r.artifactRegistry.SetIamPolicy(ctx, &iampb.SetIamPolicyRequest{
		Resource: repository.Name,
		Policy: &iampb.Policy{
			Bindings: bindings,
		},
	})
	if err != nil {
		return false, err
	}

	return true, nil
}

func IsIAMPolicyBindingEqual(want, current []*iampb.Binding) bool {
	compareBindingsFunc := func(a, b *iampb.Binding) bool {
		return proto.Equal(a, b)
	}

	sortBindingsByRole := func(i, j *iampb.Binding) int {
		return strings.Compare(i.Role, j.Role)
	}

	slices.SortFunc(want, sortBindingsByRole)
	slices.SortFunc(current, sortBindingsByRole)

	return slices.EqualFunc(want, current, compareBindingsFunc)
}

func serviceAccountNameAndAccountID(teamSlug, projectID string) (serviceAccountName, accountID string) {
	accountID = str.SlugHashPrefixTruncate(teamSlug, "gar", gcp.GoogleServiceAccountMaxLength)
	emailAddress := accountID + "@" + projectID + ".iam.gserviceaccount.com"
	serviceAccountName = "projects/" + projectID + "/serviceAccounts/" + emailAddress
	return
}

// Remove all images that are more than 90 days old, but keep the last 50 "versions" regardless of age.
// These numbers are also referenced in our own documentation at: https://doc.nais.io/how-to-guides/github-action/; try to keep them in sync.
//
// Each "build and push" includes artifacts such as signatures and attestations that seemingly count as "versions".
// Thus, an "image" actually consists of 5 artifacts at the worst (for images pushed through the nais/docker-build-push action)
//
// Documentation: https://cloud.google.com/artifact-registry/docs/repositories/cleanup-policy
func DefaultCleanupPolicies() map[string]*artifactregistrypb.CleanupPolicy {
	var keepCount int32 = 50

	keepUntilAge := time.Hour * 24 * 90
	anyTagState := artifactregistrypb.CleanupPolicyCondition_ANY

	return map[string]*artifactregistrypb.CleanupPolicy{
		"delete_old_images": {
			Id:     "delete_old_images",
			Action: artifactregistrypb.CleanupPolicy_DELETE,
			ConditionType: &artifactregistrypb.CleanupPolicy_Condition{
				Condition: &artifactregistrypb.CleanupPolicyCondition{
					TagState:  &anyTagState,
					OlderThan: durationpb.New(keepUntilAge),
				},
			},
		},
		"keep_latest_versions": {
			Id:     "keep_latest_versions",
			Action: artifactregistrypb.CleanupPolicy_KEEP,
			ConditionType: &artifactregistrypb.CleanupPolicy_MostRecentVersions{
				MostRecentVersions: &artifactregistrypb.CleanupPolicyMostRecentVersions{
					KeepCount: &keepCount,
				},
			},
		},
	}
}
