package google_gar_reconciler

import (
	"context"
	"fmt"
	"net/http"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	"cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/nais/api-reconcilers/internal/gcp"
	"github.com/nais/api-reconcilers/internal/google_token_source"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	github_team_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/github/team"
	str "github.com/nais/api-reconcilers/internal/strings"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"k8s.io/utils/ptr"
)

const (
	reconcilerName = "google:gcp:gar"

	managedByLabelName  = "managed-by"
	managedByLabelValue = "api-reconcilers"

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

func New(ctx context.Context, googleManagementProjectID, tenantDomain, workloadIdentityPoolName string, opts ...OptFunc) (reconcilers.Reconciler, error) {
	r := &garReconciler{
		googleManagementProjectID: googleManagementProjectID,
		workloadIdentityPoolName:  workloadIdentityPoolName,
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.iamService == nil || r.artifactRegistry == nil {
		builder, err := google_token_source.New(googleManagementProjectID, tenantDomain)
		if err != nil {
			return nil, err
		}

		ts, err := builder.GCP(ctx)
		if err != nil {
			return nil, fmt.Errorf("get delegated token source: %w", err)
		}

		if r.iamService == nil {
			iamService, err := iam.NewService(ctx, option.WithTokenSource(ts), option.WithHTTPClient(otelhttp.DefaultClient))
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

	if err := r.setGarRepositoryPolicy(ctx, garRepository, serviceAccount, naisTeam.GoogleGroupEmail); err != nil {
		return err
	}

	client.Teams().SetTeamExternalReferences(ctx, &protoapi.SetTeamExternalReferencesRequest{
		Slug:          naisTeam.Slug,
		GarRepository: &garRepository.Name,
	})

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
	_, err = client.Teams().SetTeamExternalReferences(ctx, &protoapi.SetTeamExternalReferencesRequest{
		Slug:          naisTeam.Slug,
		GarRepository: ptr.To(""),
	})
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
	members, err := r.getServiceAccountPolicyMembers(ctx, teamSlug, client.Reconcilers())
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

func (r *garReconciler) getServiceAccountPolicyMembers(ctx context.Context, teamSlug string, client protoapi.ReconcilersClient) ([]string, error) {
	repos, err := github_team_reconciler.GetTeamRepositories(ctx, client, teamSlug)
	if err != nil {
		return nil, err
	}

	members := make([]string, 0)
	for _, githubRepo := range repos {
		if githubRepo.Archived {
			continue
		}
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

func (r *garReconciler) setGarRepositoryPolicy(ctx context.Context, repository *artifactregistrypb.Repository, serviceAccount *iam.ServiceAccount, groupEmail *string) error {
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

	_, err := r.artifactRegistry.SetIamPolicy(ctx, &iampb.SetIamPolicyRequest{
		Resource: repository.Name,
		Policy: &iampb.Policy{
			Bindings: bindings,
		},
	})
	return err
}

func serviceAccountNameAndAccountID(teamSlug, projectID string) (serviceAccountName, accountID string) {
	accountID = str.SlugHashPrefixTruncate(teamSlug, "gar", gcp.GoogleServiceAccountMaxLength)
	emailAddress := accountID + "@" + projectID + ".iam.gserviceaccount.com"
	serviceAccountName = "projects/" + projectID + "/serviceAccounts/" + emailAddress
	return
}
