package google_gcp_reconciler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nais/api-reconcilers/internal/cmd/reconciler/config"
	"github.com/nais/api-reconcilers/internal/gcp"
	"github.com/nais/api-reconcilers/internal/google_token_source"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	str "github.com/nais/api-reconcilers/internal/strings"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/iterator"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/cloudbilling/v1"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/serviceusage/v1"
)

const (
	reconcilerName = "google:gcp:project"

	googleProjectDisplayNameMaxLength = 30
	ManagedByLabelName                = "managed-by"
	ManagedByLabelValue               = "api-reconcilers"
)

type GcpServices struct {
	CloudBillingProjectsService           *cloudbilling.ProjectsService
	CloudResourceManagerOperationsService *cloudresourcemanager.OperationsService
	CloudResourceManagerProjectsService   *cloudresourcemanager.ProjectsService
	ComputeGlobalOperationsService        *compute.GlobalOperationsService
	FirewallService                       *compute.FirewallsService
	ComputeProjectsService                *compute.ProjectsService
	IamProjectsServiceAccountsService     *iam.ProjectsServiceAccountsService
	ServiceUsageOperationsService         *serviceusage.OperationsService
	ServiceUsageService                   *serviceusage.ServicesService
	ProjectsRolesService                  *iam.ProjectsRolesService
}

type googleGcpReconciler struct {
	billingAccount string
	clusters       gcp.Clusters
	gcpServices    *GcpServices
	tenantDomain   string
	tenantName     string
	flags          config.FeatureFlags
	clusterAlias   map[string]string
}

type OptFunc func(*googleGcpReconciler)

func WithGcpServices(gcpServices *GcpServices) OptFunc {
	return func(r *googleGcpReconciler) {
		r.gcpServices = gcpServices
	}
}

func New(ctx context.Context, clusters gcp.Clusters, serviceAccountEmail, tenantDomain, tenantName, billingAccount string, clusterAlias map[string]string, flags config.FeatureFlags, opts ...OptFunc) (reconcilers.Reconciler, error) {
	if clusterAlias == nil {
		clusterAlias = make(map[string]string)
	}
	r := &googleGcpReconciler{
		billingAccount: billingAccount,
		clusters:       clusters,
		tenantDomain:   tenantDomain,
		tenantName:     tenantName,
		flags:          flags,
		clusterAlias:   clusterAlias,
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.gcpServices == nil {
		gcpServices, err := createGcpServices(ctx, serviceAccountEmail)
		if err != nil {
			return nil, err
		}

		r.gcpServices = gcpServices
	}

	return r, nil
}

func (r *googleGcpReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "GCP projects",
		Description: "Create GCP projects for the Console teams.",
		MemberAware: false,
	}
}

func (r *googleGcpReconciler) Name() string {
	return reconcilerName
}

func (r *googleGcpReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	if len(r.clusters) == 0 {
		log.Debugf("no active environments, skipping reconcile")
		return nil
	}

	if naisTeam.GoogleGroupEmail == nil {
		return fmt.Errorf("no Google Workspace group exists for team %q yet", naisTeam.Slug)
	}

	it := iterator.New[*protoapi.TeamEnvironment](ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})

	for it.Next() {
		env := it.Value()
		if !env.Gcp {
			log.WithField("environment", env.EnvironmentName).Debug("environment is not a GCP environment, skipping")
			continue
		}

		cluster, exists := r.clusters[env.EnvironmentName]
		if !exists {
			log.Warnf("environment %q is not active, skipping", env.EnvironmentName)
			continue
		}

		if _, isAlias := r.clusterAlias[env.EnvironmentName]; isAlias {
			continue
		}

		projectID := GenerateProjectID(r.tenantDomain, env.EnvironmentName, naisTeam.Slug)
		log.WithField("project_id", projectID).Debugf("generated GCP project ID")
		teamProject, err := r.getOrCreateProject(ctx, projectID, env, cluster.TeamsFolderID, naisTeam)
		if err != nil {
			return fmt.Errorf("get or create a GCP project %q for team %q in environment %q: %w", projectID, naisTeam.Slug, env.EnvironmentName, err)
		}

		envList := []string{env.EnvironmentName}
		for alias, original := range r.clusterAlias {
			if original == env.EnvironmentName {
				envList = append(envList, alias)
			}
		}

		for _, envName := range envList {
			_, err = client.Teams().SetTeamEnvironmentExternalReferences(ctx, &protoapi.SetTeamEnvironmentExternalReferencesRequest{
				Slug:            naisTeam.Slug,
				EnvironmentName: envName,
				GcpProjectId:    &teamProject.ProjectId,
			})
			if err != nil {
				return fmt.Errorf("set GCP project ID for team %q in environment %q: %w", naisTeam.Slug, envName, err)
			}
		}

		labels := map[string]string{
			"team":             naisTeam.Slug,
			"environment":      env.EnvironmentName,
			"tenant":           r.tenantName,
			ManagedByLabelName: ManagedByLabelValue,
		}
		if err := r.ensureProjectHasLabels(ctx, teamProject, labels); err != nil {
			return fmt.Errorf("set project labels: %w", err)
		}

		if err := r.setTeamProjectBillingInfo(ctx, teamProject); err != nil {
			return fmt.Errorf("set project billing info for project %q for team %q in environment %q: %w", teamProject.ProjectId, naisTeam.Slug, env.EnvironmentName, err)
		}

		cnrmServiceAccount, err := r.getOrCreateProjectCnrmServiceAccount(ctx, teamProject.ProjectId)
		if err != nil {
			return fmt.Errorf("create CNRM service account for project %q for team %q in environment %q: %w", teamProject.ProjectId, naisTeam.Slug, env.EnvironmentName, err)
		}

		cnrmRole, err := r.createCNRMRole(ctx, teamProject.ProjectId)
		if err != nil {
			return fmt.Errorf("create CNRM role for project %q for team %q in environment %q: %w", teamProject.ProjectId, naisTeam.Slug, env.EnvironmentName, err)
		}

		teamRole, err := r.createTeamRole(ctx, teamProject.ProjectId)
		if err != nil {
			return fmt.Errorf("create team role for project %q for team %q in environment %q: %w", teamProject.ProjectId, naisTeam.Slug, env.EnvironmentName, err)
		}

		if err := r.setProjectPermissions(ctx, teamProject, naisTeam, cluster.ProjectID, cnrmServiceAccount, cnrmRole.Name, teamRole.Name); err != nil {
			return fmt.Errorf("set group permissions to project %q for team %q in environment %q: %w", teamProject.ProjectId, naisTeam.Slug, env.EnvironmentName, err)
		}

		if err := r.ensureProjectHasAccessToGoogleApis(ctx, teamProject); err != nil {
			return fmt.Errorf("enable Google APIs access in project %q for team %q in environment %q: %w", teamProject.ProjectId, naisTeam.Slug, env.EnvironmentName, err)
		}

		if err := r.deleteDefaultVPCNetworkRules(ctx, teamProject, log); err != nil {
			return fmt.Errorf("delete default vpc firewall rules in project %q for team %q in environment %q: %w", teamProject.ProjectId, naisTeam.Slug, env.EnvironmentName, err)
		}

		if r.flags.AttachSharedVpc {
			if err := r.attachProjectToSharedVPC(ctx, teamProject.ProjectId, cluster.ProjectID, log); err != nil {
				return fmt.Errorf("attach project %q as service project to shared VPC for team %q in environment %q: %w", teamProject.ProjectId, naisTeam.SlackChannel, env.EnvironmentName, err)
			}
		}

	}

	return it.Err()
}

func (r *googleGcpReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	var retErrors []error

	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})

	for it.Next() {
		env := it.Value()
		if !env.Gcp || env.GcpProjectId == nil {
			log.Warning("skipping environment, no GCP project or project is already deleted")
			continue
		}

		if _, isAlias := r.clusterAlias[env.EnvironmentName]; isAlias {
			log.Infof("skipping alias environment %q", env.EnvironmentName)
			continue
		}

		projectID := *env.GcpProjectId

		log := log.WithField("gcp_project_id", projectID).WithField("environment", env.EnvironmentName)

		if _, exists := r.clusters[env.EnvironmentName]; !exists {
			log.Errorf("environment is no longer active, removing from state")
			_, err := client.Teams().SetTeamEnvironmentExternalReferences(ctx, &protoapi.SetTeamEnvironmentExternalReferencesRequest{
				Slug:            naisTeam.Slug,
				EnvironmentName: env.EnvironmentName,
				GcpProjectId:    nil,
			})
			if err != nil {
				retErrors = append(retErrors, err)
			}
			continue
		}

		_, err := r.gcpServices.CloudResourceManagerProjectsService.Delete("projects/" + projectID).Context(ctx).Do()
		if err != nil {
			var googleError *googleapi.Error
			ok := errors.As(err, &googleError)
			if !(ok && (googleError.Code == 400 || googleError.Code == 404 || googleError.Code == 403)) {
				retErrors = append(retErrors, err)
				continue
			}
		}

		_, err = client.Teams().SetTeamEnvironmentExternalReferences(ctx, &protoapi.SetTeamEnvironmentExternalReferencesRequest{
			Slug:            naisTeam.Slug,
			EnvironmentName: env.EnvironmentName,
			GcpProjectId:    nil,
		})
		if err != nil {
			retErrors = append(retErrors, err)
		}
	}

	for _, err := range retErrors {
		log.WithError(err).Errorf("error during team deletion")
	}

	if it.Err() != nil {
		return fmt.Errorf("error during team deletion: %w", it.Err())
	}

	if len(retErrors) == 0 {
		return nil
	}

	return fmt.Errorf("%d error(s) occurred during GCP project deletion", len(retErrors))
}

func (r *googleGcpReconciler) ensureProjectHasAccessToGoogleApis(ctx context.Context, project *cloudresourcemanager.Project) error {
	desiredServiceIDs := map[string]struct{}{
		"compute.googleapis.com":              {},
		"cloudbilling.googleapis.com":         {},
		"storage-component.googleapis.com":    {},
		"storage-api.googleapis.com":          {},
		"sqladmin.googleapis.com":             {},
		"sql-component.googleapis.com":        {},
		"cloudresourcemanager.googleapis.com": {},
		"secretmanager.googleapis.com":        {},
		"pubsub.googleapis.com":               {},
		"logging.googleapis.com":              {},
		"bigquery.googleapis.com":             {},
		"cloudtrace.googleapis.com":           {},
		"servicenetworking.googleapis.com":    {},
		"datamigration.googleapis.com":        {},
	}

	response, err := r.gcpServices.ServiceUsageService.List(project.Name).Filter("state:ENABLED").Context(ctx).Do()
	if err != nil {
		return err
	}

	if response.HTTPStatusCode != http.StatusOK {
		return fmt.Errorf("non OK http status: %v", response.HTTPStatusCode)
	}

	// Take already enabled services out of the list of services we want to enable
	for _, enabledService := range response.Services {
		delete(desiredServiceIDs, enabledService.Config.Name)
	}

	if len(desiredServiceIDs) == 0 {
		return nil
	}

	servicesToEnable := make([]string, 0, len(desiredServiceIDs))
	for key := range desiredServiceIDs {
		servicesToEnable = append(servicesToEnable, key)
	}

	req := &serviceusage.BatchEnableServicesRequest{
		ServiceIds: servicesToEnable,
	}

	operation, err := r.gcpServices.ServiceUsageService.BatchEnable(project.Name, req).Context(ctx).Do()
	if err != nil {
		return err
	}

	for !operation.Done {
		time.Sleep(1 * time.Second)
		operation, err = r.gcpServices.ServiceUsageOperationsService.Get(operation.Name).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("poll operation: %w", err)
		}
	}

	if operation.Error != nil {
		return fmt.Errorf("complete operation: %s", operation.Error.Message)
	}

	return nil
}

func (r *googleGcpReconciler) getOrCreateProject(ctx context.Context, projectID string, environment *protoapi.TeamEnvironment, parentFolderID int64, naisTeam *protoapi.Team) (*cloudresourcemanager.Project, error) {
	if environment.GcpProjectId != nil {
		response, err := r.gcpServices.CloudResourceManagerProjectsService.Search().Query("id:" + *environment.GcpProjectId).Context(ctx).Do()
		if err != nil {
			return nil, err
		}

		if len(response.Projects) == 1 {
			return response.Projects[0], nil
		}

		if len(response.Projects) > 1 {
			return nil, fmt.Errorf("multiple projects with id: %q found, unable to continue", *environment.GcpProjectId)
		}

		return nil, fmt.Errorf("no project with id: %q found, unable to continue", *environment.GcpProjectId)
	}

	project := &cloudresourcemanager.Project{
		DisplayName: GetProjectDisplayName(naisTeam.Slug, environment.EnvironmentName),
		Parent:      "folders/" + strconv.FormatInt(parentFolderID, 10),
		ProjectId:   projectID,
	}
	operation, err := r.gcpServices.CloudResourceManagerProjectsService.Create(project).Do()
	if err != nil {
		var googleError *googleapi.Error
		ok := errors.As(err, &googleError)
		if !ok {
			return nil, fmt.Errorf("create GCP project: %w", err)
		}

		if googleError.Code != 409 {
			return nil, fmt.Errorf("create GCP project: %w", err)
		}

		// the project already exists, adopt
		response, err := r.gcpServices.CloudResourceManagerProjectsService.Search().Query("id:" + projectID).Do()
		if err != nil {
			return nil, fmt.Errorf("find existing GCP project: %w", err)
		}

		if len(response.Projects) != 1 {
			return nil, fmt.Errorf("invalid number of projects in response: %+v", response.Projects)
		}

		return response.Projects[0], nil
	}

	response, err := r.getOperationResponse(ctx, operation)
	if err != nil {
		return nil, fmt.Errorf("get result from GCP project creation: %w", err)
	}

	createdProject := &cloudresourcemanager.Project{}
	err = json.Unmarshal(response, createdProject)
	if err != nil {
		return nil, fmt.Errorf("convert operation response to the Created GCP project: %w", err)
	}

	return createdProject, nil
}

// setProjectPermissions Make sure that the project has the necessary permissions, and don't remove permissions we don't
// control
func (r *googleGcpReconciler) setProjectPermissions(ctx context.Context, teamProject *cloudresourcemanager.Project, naisTeam *protoapi.Team, clusterProjectID string, cnrmServiceAccount *iam.ServiceAccount, cnrmRoleName, teamRoleName string) error {
	member := "serviceAccount:" + clusterProjectID + ".svc.id.goog[cnrm-system/cnrm-controller-manager-" + naisTeam.Slug + "]"
	_, err := r.gcpServices.IamProjectsServiceAccountsService.SetIamPolicy(cnrmServiceAccount.Name, &iam.SetIamPolicyRequest{
		Policy: &iam.Policy{
			Bindings: []*iam.Binding{
				{
					Members: []string{member},
					Role:    "roles/iam.workloadIdentityUser",
				},
			},
		},
	}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("assign roles for CNRM service account: %w", err)
	}

	policy, err := r.gcpServices.CloudResourceManagerProjectsService.GetIamPolicy(teamProject.Name, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("retrieve existing GCP project IAM policy: %w", err)
	}

	newBindings, updated := CalculateRoleBindings(policy.Bindings, map[string][]string{
		"roles/owner": {"group:" + *naisTeam.GoogleGroupEmail},
		cnrmRoleName:  {"serviceAccount:" + cnrmServiceAccount.Email},
		teamRoleName:  {"group:" + *naisTeam.GoogleGroupEmail},
	})

	if !updated {
		return nil
	}

	policy.Bindings = newBindings
	_, err = r.gcpServices.CloudResourceManagerProjectsService.SetIamPolicy(teamProject.Name, &cloudresourcemanager.SetIamPolicyRequest{
		Policy: policy,
	}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("assign GCP project IAM policy: %w", err)
	}

	return nil
}

// getOrCreateProjectCnrmServiceAccount Get the CNRM service account for the project in this env. If the service account
// does not exist, attempt to create it, and then return it.
func (r *googleGcpReconciler) getOrCreateProjectCnrmServiceAccount(ctx context.Context, teamProjectID string) (*iam.ServiceAccount, error) {
	email := "nais-sa-cnrm@" + teamProjectID + ".iam.gserviceaccount.com"
	name := "projects/-/serviceAccounts/" + email
	serviceAccount, err := r.gcpServices.IamProjectsServiceAccountsService.Get(name).Context(ctx).Do()
	if err == nil {
		return serviceAccount, nil
	}

	createServiceAccountRequest := &iam.CreateServiceAccountRequest{
		AccountId: "nais-sa-cnrm",
		ServiceAccount: &iam.ServiceAccount{
			DisplayName: "CNRM service account",
			Description: "Managed by github.com/nais/api-reconcilers",
		},
	}
	serviceAccount, err = r.gcpServices.IamProjectsServiceAccountsService.Create("projects/"+teamProjectID, createServiceAccountRequest).Do()
	if err != nil {
		return nil, err
	}

	return serviceAccount, nil
}

func (r *googleGcpReconciler) setTeamProjectBillingInfo(ctx context.Context, project *cloudresourcemanager.Project) error {
	info, err := r.gcpServices.CloudBillingProjectsService.GetBillingInfo(project.Name).Context(ctx).Do()
	if err != nil {
		return err
	}

	if info.BillingAccountName == r.billingAccount {
		return nil
	}

	_, err = r.gcpServices.CloudBillingProjectsService.UpdateBillingInfo(project.Name, &cloudbilling.ProjectBillingInfo{
		BillingAccountName: r.billingAccount,
	}).Context(ctx).Do()
	if err != nil {
		return err
	}

	return nil
}

func (r *googleGcpReconciler) getOperationResponse(ctx context.Context, operation *cloudresourcemanager.Operation) (googleapi.RawMessage, error) {
	var err error
	for !operation.Done {
		time.Sleep(1 * time.Second) // Make sure not to hammer the Operation API
		operation, err = r.gcpServices.CloudResourceManagerOperationsService.Get(operation.Name).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("poll operation: %w", err)
		}
	}

	if operation.Error != nil {
		return nil, fmt.Errorf("complete operation: %s", operation.Error.Message)
	}

	return operation.Response, nil
}

func (r *googleGcpReconciler) ensureProjectHasLabels(ctx context.Context, project *cloudresourcemanager.Project, labels map[string]string) error {
	operation, err := r.gcpServices.CloudResourceManagerProjectsService.Patch(project.Name, &cloudresourcemanager.Project{
		Labels: labels,
	}).Context(ctx).Do()
	if err != nil {
		return err
	}

	_, err = r.getOperationResponse(ctx, operation)
	return err
}

// createGcpServices Creates the GCP services used by the reconciler
func createGcpServices(ctx context.Context, serviceAccountEmail string) (*GcpServices, error) {
	ts, err := google_token_source.GcpTokenSource(ctx, serviceAccountEmail)
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

	iamService, err := iam.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve IAM service service: %w", err)
	}

	cloudBillingService, err := cloudbilling.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve cloud billing service: %w", err)
	}

	serviceUsageService, err := serviceusage.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve service usage service: %w", err)
	}

	computeService, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve compute service: %w", err)
	}

	return &GcpServices{
		CloudBillingProjectsService:           cloudBillingService.Projects,
		CloudResourceManagerOperationsService: cloudResourceManagerService.Operations,
		CloudResourceManagerProjectsService:   cloudResourceManagerService.Projects,
		ComputeGlobalOperationsService:        computeService.GlobalOperations,
		FirewallService:                       computeService.Firewalls,
		ComputeProjectsService:                computeService.Projects,
		IamProjectsServiceAccountsService:     iamService.Projects.ServiceAccounts,
		ServiceUsageOperationsService:         serviceUsageService.Operations,
		ServiceUsageService:                   serviceUsageService.Services,
		ProjectsRolesService:                  iamService.Projects.Roles,
	}, nil
}

func (r *googleGcpReconciler) deleteDefaultVPCNetworkRules(ctx context.Context, project *cloudresourcemanager.Project, log logrus.FieldLogger) error {
	rulesToDelete := []struct {
		name     string
		priority int64
	}{
		{name: "default-allow-icmp", priority: 65534},
		{name: "default-allow-rdp", priority: 65534},
		{name: "default-allow-ssh", priority: 65534},
	}

	rules, err := r.gcpServices.FirewallService.List(project.ProjectId).Context(ctx).Do()
	if err != nil {
		return err
	}

	for _, rule := range rules.Items {
		for _, deleteTemplate := range rulesToDelete {
			if rule.Name == deleteTemplate.name && rule.Priority == deleteTemplate.priority {
				operation, err := r.gcpServices.FirewallService.Delete(project.ProjectId, rule.Name).Context(ctx).Do()
				if err != nil {
					return err
				}

				for operation.Status != "DONE" {
					operation, err = r.gcpServices.ComputeGlobalOperationsService.Wait(project.ProjectId, operation.Name).Context(ctx).Do()
					if err != nil {
						return err
					}
				}
				log.Infof("deleted default firewall rule %q in project %q", rule.Name, project.ProjectId)
			}
		}
	}
	return nil
}

func (r *googleGcpReconciler) attachProjectToSharedVPC(ctx context.Context, teamProjectId string, clusterProjectId string, log logrus.FieldLogger) error {
	getXpnResourcesResult, err := r.gcpServices.ComputeProjectsService.GetXpnResources(clusterProjectId).Context(ctx).Do()
	if err != nil {
		return err
	}
	for _, xpnResource := range getXpnResourcesResult.Resources {
		if xpnResource.Id == teamProjectId {
			log.Debugf("Team project %q is already attached to shared vpc in %q", teamProjectId, clusterProjectId)
			return nil
		}
	}

	req := &compute.ProjectsEnableXpnResourceRequest{
		XpnResource: &compute.XpnResourceId{
			Id:   teamProjectId,
			Type: "PROJECT",
		},
	}
	operation, err := r.gcpServices.ComputeProjectsService.EnableXpnResource(clusterProjectId, req).Context(ctx).Do()
	if err != nil {
		if googleapi.IsNotModified(err) {
			return nil
		}
		return err
	}

	for operation.Status != "DONE" {
		operation, err = r.gcpServices.ComputeGlobalOperationsService.Wait(clusterProjectId, operation.Name).Context(ctx).Do()
		if err != nil {
			return err
		}
	}
	log.Infof("Attached team project %q as service project to shared vpc in %q", teamProjectId, clusterProjectId)

	return nil
}

// GenerateProjectID Generate a unique project ID for the team in a given environment in a deterministic fashion
func GenerateProjectID(domain, environment, teamSlug string) string {
	hasher := sha256.New()
	hasher.Write([]byte(teamSlug))
	hasher.Write([]byte{0})
	hasher.Write([]byte(environment))
	hasher.Write([]byte{0})
	hasher.Write([]byte(domain))

	parts := make([]string, 3)
	parts[0] = strings.TrimSuffix(str.Truncate(teamSlug, 20), "-")
	parts[1] = strings.TrimSuffix(str.Truncate(environment, 4), "-")
	parts[2] = str.Truncate(hex.EncodeToString(hasher.Sum(nil)), 4)

	return strings.Join(parts, "-")
}

// GetProjectDisplayName Get the display name of a project for a team in a given environment
func GetProjectDisplayName(teamSlug, environment string) string {
	suffix := "-" + environment
	maxSlugLength := googleProjectDisplayNameMaxLength - len(suffix)
	prefix := str.Truncate(teamSlug, maxSlugLength)
	prefix = strings.TrimSuffix(prefix, "-")
	return prefix + suffix
}

// CalculateRoleBindings Given a set of role bindings, make sure the ones in requiredRoleBindings are present
func CalculateRoleBindings(existingRoleBindings []*cloudresourcemanager.Binding, requiredRoleBindings map[string][]string) ([]*cloudresourcemanager.Binding, bool) {
	updated := false

REQUIRED:
	for role, members := range requiredRoleBindings {
		for idx, binding := range existingRoleBindings {
			if binding.Role != role {
				continue
			}
			for _, member := range members {
				if !contains(binding.Members, member) {
					existingRoleBindings[idx].Members = append(existingRoleBindings[idx].Members, member)
					updated = true
				}
			}
			continue REQUIRED
		}

		// the required role is missing altogether from the existing bindings
		existingRoleBindings = append(existingRoleBindings, &cloudresourcemanager.Binding{
			Members: members,
			Role:    role,
		})
		updated = true
	}

	return existingRoleBindings, updated
}

// contains Check if a specific value is in a slice of strings
func contains(strings []string, contains string) bool {
	for _, value := range strings {
		if value == contains {
			return true
		}
	}
	return false
}
