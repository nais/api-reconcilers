package grafana_reconciler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	grafanaaccesscontrol "github.com/grafana/grafana-openapi-client-go/client/access_control"
	grafanaadminusers "github.com/grafana/grafana-openapi-client-go/client/admin_users"
	grafanafolders "github.com/grafana/grafana-openapi-client-go/client/folders"
	grafanaprovisioning "github.com/grafana/grafana-openapi-client-go/client/provisioning"
	grafanaserviceaccounts "github.com/grafana/grafana-openapi-client-go/client/service_accounts"
	grafanateams "github.com/grafana/grafana-openapi-client-go/client/teams"
	grafanausers "github.com/grafana/grafana-openapi-client-go/client/users"
	"github.com/grafana/grafana-openapi-client-go/models"
	"github.com/nais/api-reconcilers/internal/cmd/reconciler/config"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/exp/maps"
)

const (
	grafanaReconcilerName = "grafana"
	contactPointType      = "slack"

	// Timing settings optimized for immediate grouping with reasonable repeat intervals
	defaultGroupWait      = "0s"
	defaultGroupInterval  = "5m"
	defaultRepeatInterval = "3h"

	defaultSlackUsername = "Grafana"
	discardMuteTiming    = "nais-unconfigured-environment"
)

type UsersClientService interface {
	GetUserByLoginOrEmailWithParams(params *grafanausers.GetUserByLoginOrEmailParams, opts ...grafanausers.ClientOption) (*grafanausers.GetUserByLoginOrEmailOK, error)
}

type TeamsClientService interface {
	SearchTeams(params *grafanateams.SearchTeamsParams, opts ...grafanateams.ClientOption) (*grafanateams.SearchTeamsOK, error)
	CreateTeamWithParams(params *grafanateams.CreateTeamParams, opts ...grafanateams.ClientOption) (*grafanateams.CreateTeamOK, error)
	GetTeamMembersWithParams(params *grafanateams.GetTeamMembersParams, opts ...grafanateams.ClientOption) (*grafanateams.GetTeamMembersOK, error)
	RemoveTeamMemberWithParams(params *grafanateams.RemoveTeamMemberParams, opts ...grafanateams.ClientOption) (*grafanateams.RemoveTeamMemberOK, error)
	AddTeamMemberWithParams(params *grafanateams.AddTeamMemberParams, opts ...grafanateams.ClientOption) (*grafanateams.AddTeamMemberOK, error)
	DeleteTeamByID(teamID string, opts ...grafanateams.ClientOption) (*grafanateams.DeleteTeamByIDOK, error)
}

type FoldersClientService interface {
	DeleteFolder(params *grafanafolders.DeleteFolderParams, opts ...grafanafolders.ClientOption) (*grafanafolders.DeleteFolderOK, error)
	GetFolders(params *grafanafolders.GetFoldersParams, opts ...grafanafolders.ClientOption) (*grafanafolders.GetFoldersOK, error)
	GetFolderByUIDWithParams(params *grafanafolders.GetFolderByUIDParams, opts ...grafanafolders.ClientOption) (*grafanafolders.GetFolderByUIDOK, error)
	CreateFolderWithParams(params *grafanafolders.CreateFolderParams, opts ...grafanafolders.ClientOption) (*grafanafolders.CreateFolderOK, error)
	UpdateFolderWithParams(params *grafanafolders.UpdateFolderParams, opts ...grafanafolders.ClientOption) (*grafanafolders.UpdateFolderOK, error)
}

type FolderPermissionsClientService interface {
	GetFolderPermissionListWithParams(params *grafanafolders.GetFolderPermissionListParams, opts ...grafanafolders.ClientOption) (*grafanafolders.GetFolderPermissionListOK, error)
	UpdateFolderPermissionsWithParams(params *grafanafolders.UpdateFolderPermissionsParams, opts ...grafanafolders.ClientOption) (*grafanafolders.UpdateFolderPermissionsOK, error)
}

type AccessControlClientService interface {
	GetResourcePermissionsWithParams(params *grafanaaccesscontrol.GetResourcePermissionsParams, opts ...grafanaaccesscontrol.ClientOption) (*grafanaaccesscontrol.GetResourcePermissionsOK, error)
	SetResourcePermissions(params *grafanaaccesscontrol.SetResourcePermissionsParams, opts ...grafanaaccesscontrol.ClientOption) (*grafanaaccesscontrol.SetResourcePermissionsOK, error)
}

type ServiceAccountsClientService interface {
	SearchOrgServiceAccountsWithPaging(params *grafanaserviceaccounts.SearchOrgServiceAccountsWithPagingParams, opts ...grafanaserviceaccounts.ClientOption) (*grafanaserviceaccounts.SearchOrgServiceAccountsWithPagingOK, error)
	CreateServiceAccount(params *grafanaserviceaccounts.CreateServiceAccountParams, opts ...grafanaserviceaccounts.ClientOption) (*grafanaserviceaccounts.CreateServiceAccountCreated, error)
}

type AdminUsersClientService interface {
	AdminCreateUserWithParams(params *grafanaadminusers.AdminCreateUserParams, opts ...grafanaadminusers.ClientOption) (*grafanaadminusers.AdminCreateUserOK, error)
}

type ProvisioningClientService interface {
	DeleteContactpointsWithParams(params *grafanaprovisioning.DeleteContactpointsParams, opts ...grafanaprovisioning.ClientOption) (*grafanaprovisioning.DeleteContactpointsAccepted, error)
	GetAlertRules(opts ...grafanaprovisioning.ClientOption) (*grafanaprovisioning.GetAlertRulesOK, error)
	GetTemplate(name string, opts ...grafanaprovisioning.ClientOption) (*grafanaprovisioning.GetTemplateOK, error)
	PutTemplate(params *grafanaprovisioning.PutTemplateParams, opts ...grafanaprovisioning.ClientOption) (*grafanaprovisioning.PutTemplateAccepted, error)
	GetContactpoints(params *grafanaprovisioning.GetContactpointsParams, opts ...grafanaprovisioning.ClientOption) (*grafanaprovisioning.GetContactpointsOK, error)
	PostContactpoints(params *grafanaprovisioning.PostContactpointsParams, opts ...grafanaprovisioning.ClientOption) (*grafanaprovisioning.PostContactpointsAccepted, error)
	PutContactpoint(params *grafanaprovisioning.PutContactpointParams, opts ...grafanaprovisioning.ClientOption) (*grafanaprovisioning.PutContactpointAccepted, error)
	GetPolicyTree(opts ...grafanaprovisioning.ClientOption) (*grafanaprovisioning.GetPolicyTreeOK, error)
	PutPolicyTree(params *grafanaprovisioning.PutPolicyTreeParams, opts ...grafanaprovisioning.ClientOption) (*grafanaprovisioning.PutPolicyTreeAccepted, error)
	GetMuteTimingsWithParams(params *grafanaprovisioning.GetMuteTimingsParams, opts ...grafanaprovisioning.ClientOption) (*grafanaprovisioning.GetMuteTimingsOK, error)
	PostMuteTiming(params *grafanaprovisioning.PostMuteTimingParams, opts ...grafanaprovisioning.ClientOption) (*grafanaprovisioning.PostMuteTimingCreated, error)
}

type grafanaReconciler struct {
	users             UsersClientService
	teams             TeamsClientService
	folders           FoldersClientService
	folderPermissions FolderPermissionsClientService
	rbac              AccessControlClientService
	serviceAccounts   ServiceAccountsClientService
	adminUsers        AdminUsersClientService
	provisioning      ProvisioningClientService
	flags             config.FeatureFlags
	slackWebhookURL   string
	alertingMu        sync.Mutex

	// Template management - ensures templates are created only once
	templatesInitialized bool

	// Metrics for monitoring Grafana reconciler performance
	metricContactPointsCreated    metric.Int64Counter
	metricContactPointsFailed     metric.Int64Counter
	metricPolicyTreeSize          metric.Int64Gauge
	metricPolicyTreeUpdates       metric.Int64Counter
	metricPolicyTreeUpdatesFailed metric.Int64Counter
}

func New(
	users UsersClientService,
	teams TeamsClientService,
	folders FoldersClientService,
	folderPermissions FolderPermissionsClientService,
	rbac AccessControlClientService,
	serviceAccounts ServiceAccountsClientService,
	adminUsers AdminUsersClientService,
	provisioning ProvisioningClientService,
	flags config.FeatureFlags,
	slackWebhookURL string,
) reconcilers.Reconciler {
	meter := otel.Meter("grafana-reconciler")

	contactPointsCreated, _ := meter.Int64Counter("grafana_contact_points_created_total",
		metric.WithDescription("Total number of Grafana contact points created"))

	contactPointsFailed, _ := meter.Int64Counter("grafana_contact_points_failed_total",
		metric.WithDescription("Total number of Grafana contact points that failed to create"))

	policyTreeSize, _ := meter.Int64Gauge("grafana_policy_tree_size",
		metric.WithDescription("Current number of routes in the Grafana notification policy tree"))

	policyTreeUpdates, _ := meter.Int64Counter("grafana_policy_tree_updates_total",
		metric.WithDescription("Total number of Grafana policy tree updates"))

	policyTreeUpdatesFailed, _ := meter.Int64Counter("grafana_policy_tree_updates_failed_total",
		metric.WithDescription("Total number of Grafana policy tree updates that failed"))

	return &grafanaReconciler{
		users:             users,
		teams:             teams,
		folders:           folders,
		folderPermissions: folderPermissions,
		rbac:              rbac,
		serviceAccounts:   serviceAccounts,
		adminUsers:        adminUsers,
		provisioning:      provisioning,
		flags:             flags,
		slackWebhookURL:   slackWebhookURL,

		metricContactPointsCreated:    contactPointsCreated,
		metricContactPointsFailed:     contactPointsFailed,
		metricPolicyTreeSize:          policyTreeSize,
		metricPolicyTreeUpdates:       policyTreeUpdates,
		metricPolicyTreeUpdatesFailed: policyTreeUpdatesFailed,
	}
}

func (r *grafanaReconciler) Name() string {
	return grafanaReconcilerName
}

func (r *grafanaReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "Grafana",
		Description: "Create and reconcile Grafana service accounts and permissions for teams.",
		MemberAware: true,
	}
}

func (r *grafanaReconciler) createNotificationTemplates(ctx context.Context) error {
	// Only create templates once across all team reconciliations
	if r.templatesInitialized {
		return nil
	}

	templateName := "nais.slack"

	// Define the desired template content
	desiredContent := `{{ define "alert_severity_prefix_emoji" -}}
	{{- if ne .Status "firing" -}}
:solved:
	{{- else if eq .CommonLabels.severity "critical" -}}
:fire:
	{{- else if eq .CommonLabels.severity "warning" -}}
:warning:
	{{- end -}}
{{- end -}}

{{ define "nais.slack.title" -}}
	{{ template "alert_severity_prefix_emoji" . }} [{{- .Status | toUpper -}}{{- if eq .Status "firing" }} x {{ len .Alerts.Firing }}{{- end }} | {{- if .CommonLabels.env }} {{ .CommonLabels.env | toUpper }}{{- else }} UNKNOWN{{- end }} ] || {{- if .CommonLabels.alertname }} {{ .CommonLabels.alertname }}{{- else }} ALERT{{- end -}}
{{- end -}}

{{ define "nais.slack.body" -}}
{{- range .Alerts -}}
{{- if gt (len .Annotations) 0 }}
{{ .Annotations.summary }}
{{- if eq .Status "firing" }}
{{- if .Annotations.description }}
*Description*: {{ .Annotations.description }}
{{- end }}
{{- if .Annotations.runbook_url }}
*Runbook URL*: {{ .Annotations.runbook_url }}
{{- end }}
{{- if .Annotations.action }}
*Action*: {{ .Annotations.action }}
{{- end }}
{{- if .Annotations.consequence }}
*Consequence*: {{ .Annotations.consequence }}
{{- end }}
{{- end }}
{{- with .Labels.SortedPairs }}
Labels:
{{- range . }}
{{- if or (eq .Name "app") (eq .Name "team") (eq .Name "env") }}
• {{ .Name }}: ` + "`" + `{{ .Value }}` + "`" + `
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}`

	// Check if template exists and get current content for drift detection
	resp, err := r.provisioning.GetTemplate(templateName)

	needsUpdate := false
	if err != nil || resp == nil {
		// Template doesn't exist, needs creation
		needsUpdate = true
	} else if resp != nil && resp.Payload != nil && resp.Payload.Template != desiredContent {
		// Template exists but content differs (drift detected), needs update
		needsUpdate = true
	}

	if needsUpdate {
		// Use PUT for both creation and updates (idempotent for templates)
		templateContent := &models.NotificationTemplateContent{
			Template: desiredContent,
		}

		putParams := &grafanaprovisioning.PutTemplateParams{
			Name: templateName,
			Body: templateContent,
		}
		putParams.SetContext(ctx)

		_, operationErr := r.provisioning.PutTemplate(putParams)
		if operationErr != nil {
			return fmt.Errorf("creating/updating notification template %s: %w", templateName, operationErr)
		}
	}

	// Mark templates as initialized to prevent future calls
	r.templatesInitialized = true
	return nil
}

func (r *grafanaReconciler) buildSlackContactPointSettings(slackChannel string) map[string]any {
	return map[string]any{
		"recipient":  slackChannel,
		"username":   defaultSlackUsername,
		"icon_emoji": ":grafana:",
		"color":      "{{ if eq .Status \"firing\" }}#D63232{{ else }}#36a64f{{ end }}",
		"title":      "{{ template \"nais.slack.title\" . }}",
		"text":       "{{ template \"nais.slack.body\" . }}",
		"url":        r.slackWebhookURL,
	}
}

func (r *grafanaReconciler) getOrCreateTeam(ctx context.Context, teamName string) (int64, error) {
	params := &grafanateams.SearchTeamsParams{
		Query:   &teamName,
		Context: ctx,
	}

	searchResp, err := r.teams.SearchTeams(params)
	if err != nil {
		return 0, err
	}

	for _, team := range searchResp.Payload.Teams {
		if team != nil && team.Name != nil && *team.Name == teamName {
			if team.ID == nil {
				return 0, fmt.Errorf("team %s has no ID", teamName)
			}
			return *team.ID, nil
		}
	}

	createResp, err := r.teams.CreateTeamWithParams(&grafanateams.CreateTeamParams{
		Body: &models.CreateTeamCommand{
			Name: &teamName,
		},
		Context: ctx,
	})
	if err != nil {
		return 0, err
	}

	return createResp.Payload.TeamID, nil
}

func (r *grafanaReconciler) getOrCreateFolder(ctx context.Context, teamName string) (string, error) {
	folderUID := "nais-" + teamName
	limit := int64(1000)
	var stableFolder, titleMatch *models.FolderSearchHit
	titleMatches := 0
	for page := int64(1); ; page++ {
		resp, err := r.folders.GetFolders(&grafanafolders.GetFoldersParams{
			Limit:   &limit,
			Page:    &page,
			Context: ctx,
		})
		if err != nil {
			return "", fmt.Errorf("listing folders: %w", err)
		}

		for _, folder := range resp.Payload {
			if folder.ParentUID != "" {
				continue
			}
			if folder.UID == folderUID {
				stableFolder = folder
			}
			if folder.Title == teamName {
				titleMatches++
				titleMatch = folder
			}
		}
		if len(resp.Payload) < int(limit) {
			break
		}
	}

	if stableFolder != nil || titleMatches > 0 {
		folder := stableFolder
		if folder == nil {
			if titleMatches > 1 {
				return "", fmt.Errorf("found %d top-level folders titled %q; cannot determine the team folder", titleMatches, teamName)
			}
			folder = titleMatch
		} else if folder.Title != teamName && titleMatches > 0 {
			return "", fmt.Errorf("folder %q has title %q, but another top-level folder is titled %q", folderUID, folder.Title, teamName)
		}
		if folder.UID == "" {
			return "", fmt.Errorf("folder %s has no UID", teamName)
		}

		current, err := r.folders.GetFolderByUIDWithParams(&grafanafolders.GetFolderByUIDParams{
			FolderUID: folder.UID,
			Context:   ctx,
		})
		if err != nil {
			return "", fmt.Errorf("getting folder %s: %w", teamName, err)
		}
		update := &models.UpdateFolderCommand{
			Description: "Reconciled by nais",
			Version:     current.Payload.Version,
		}
		if folder == stableFolder && folder.Title != teamName {
			update.Title = teamName
		}
		_, err = r.folders.UpdateFolderWithParams(&grafanafolders.UpdateFolderParams{
			FolderUID: folder.UID,
			Body:      update,
			Context:   ctx,
		})
		if err != nil {
			return "", fmt.Errorf("marking folder %s as valid: %w", teamName, err)
		}
		return folder.UID, nil
	}

	if len(folderUID) > 40 {
		return "", fmt.Errorf("folder UID %q exceeds Grafana's 40-character limit", folderUID)
	}

	resp, err := r.folders.CreateFolderWithParams(&grafanafolders.CreateFolderParams{
		Body: &models.CreateFolderCommand{
			Title:       teamName,
			UID:         folderUID,
			Description: "Created by api-reconciler",
		},
		Context: ctx,
	})
	if err != nil {
		return "", fmt.Errorf("creating folder %s: %w", teamName, err)
	}
	if resp.Payload == nil || resp.Payload.UID != folderUID {
		return "", fmt.Errorf("created folder %s did not return expected UID %q", teamName, folderUID)
	}
	return folderUID, nil
}

func (r *grafanaReconciler) setFolderTeamPermissions(ctx context.Context, folderUID string, teamID int64) error {
	const (
		viewPermission models.PermissionType = 1
		editPermission models.PermissionType = 2
	)

	existing, err := r.folderPermissions.GetFolderPermissionListWithParams(&grafanafolders.GetFolderPermissionListParams{
		FolderUID: folderUID,
		Context:   ctx,
	})
	if err != nil {
		return fmt.Errorf("getting folder permissions: %w", err)
	}

	permissions := make([]*models.DashboardACLUpdateItem, 0, len(existing.Payload)+3)
	var viewerFound, editorFound, teamPermissionFound, changed bool
	for _, entry := range existing.Payload {
		if entry.Inherited {
			if entry.Role != "Admin" && entry.TeamID != teamID && entry.Permission > viewPermission {
				return fmt.Errorf("folder %s has inherited Edit or Admin permission that cannot be reduced", folderUID)
			}
			continue
		}
		if entry.Role == "Admin" {
			continue
		}
		switch entry.Role {
		case "Viewer":
			viewerFound = true
		case "Editor":
			editorFound = true
		case "":
			if entry.TeamID == 0 && entry.UserID == 0 {
				return fmt.Errorf("folder %s has a permission without a user, team or role", folderUID)
			}
		default:
			return fmt.Errorf("folder %s has unsupported role %q", folderUID, entry.Role)
		}

		permission := viewPermission
		if entry.TeamID == teamID {
			teamPermissionFound = true
			permission = max(entry.Permission, editPermission)
		}
		if permission != entry.Permission {
			changed = true
		}
		permissions = append(permissions, &models.DashboardACLUpdateItem{
			Role:       entry.Role,
			TeamID:     entry.TeamID,
			UserID:     entry.UserID,
			Permission: permission,
		})
	}

	if !viewerFound {
		permissions = append(permissions, &models.DashboardACLUpdateItem{Role: "Viewer", Permission: viewPermission})
		changed = true
	}
	if !editorFound {
		permissions = append(permissions, &models.DashboardACLUpdateItem{Role: "Editor", Permission: viewPermission})
		changed = true
	}
	if !teamPermissionFound {
		permissions = append(permissions, &models.DashboardACLUpdateItem{
			TeamID:     teamID,
			Permission: editPermission,
		})
		changed = true
	}
	if !changed {
		return nil
	}

	_, err = r.folderPermissions.UpdateFolderPermissionsWithParams(&grafanafolders.UpdateFolderPermissionsParams{
		FolderUID: folderUID,
		Body:      &models.UpdateDashboardACLCommand{Items: permissions},
		Context:   ctx,
	})
	if err != nil {
		return fmt.Errorf("updating folder permissions: %w", err)
	}
	return nil
}

func (r *grafanaReconciler) getOrCreateUser(ctx context.Context, user *protoapi.User) (int64, error) {
	existingUser, err := r.users.GetUserByLoginOrEmailWithParams(&grafanausers.GetUserByLoginOrEmailParams{
		LoginOrEmail: user.GetEmail(),
		Context:      ctx,
	})
	if err == nil {
		return existingUser.GetPayload().ID, nil
	}

	newUser, err := r.adminUsers.AdminCreateUserWithParams(&grafanaadminusers.AdminCreateUserParams{
		Body: &models.AdminCreateUserForm{
			Email:    user.GetEmail(),
			Login:    user.GetEmail(),
			Name:     user.GetName(),
			Password: models.Password(createSecurePassword()),
		},
		Context: ctx,
	})
	if err != nil {
		return 0, err
	}

	return newUser.GetPayload().ID, nil
}

func (r *grafanaReconciler) syncTeamMembers(ctx context.Context, teamID int64, naisTeamMembers []*protoapi.TeamMember, grafanaUserIDMap map[string]int64) error {
	teamIDString := strconv.Itoa(int(teamID))
	grafanaExistingMembers, err := r.teams.GetTeamMembersWithParams(&grafanateams.GetTeamMembersParams{
		TeamID:  teamIDString,
		Context: ctx,
	})
	if err != nil {
		return err
	}

	existingMembers := make(map[string]int64)
	for _, member := range grafanaExistingMembers.GetPayload() {
		existingMembers[member.Email] = member.UserID
	}

	membersToRemove := make(map[int64]string)
	for email, userID := range existingMembers {
		if !grafanaMemberExistsInTeamMembers(naisTeamMembers, email) {
			membersToRemove[userID] = email
		}
	}

	grafanaMemberEmails := maps.Keys(existingMembers)

	membersToAdd := make([]string, 0)
	for _, user := range naisTeamMembers {
		email := user.GetUser().GetEmail()
		if !teamMemberExistsInGrafanaMembers(grafanaMemberEmails, email) {
			membersToAdd = append(membersToAdd, email)
		}
	}

	for userID := range membersToRemove {
		_, err = r.teams.RemoveTeamMemberWithParams(&grafanateams.RemoveTeamMemberParams{
			TeamID:  teamIDString,
			UserID:  userID,
			Context: ctx,
		})
		if err != nil {
			return err
		}
	}

	for _, email := range membersToAdd {
		_, err = r.teams.AddTeamMemberWithParams(&grafanateams.AddTeamMemberParams{
			Body: &models.AddTeamMemberCommand{
				UserID: new(grafanaUserIDMap[email]),
			},
			TeamID:  teamIDString,
			Context: ctx,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func grafanaMemberExistsInTeamMembers(naisTeamMembers []*protoapi.TeamMember, email string) bool {
	for _, user := range naisTeamMembers {
		if strings.EqualFold(email, user.GetUser().Email) {
			return true
		}
	}
	return false
}

func teamMemberExistsInGrafanaMembers(grafanaTeamMemberEmails []string, email string) bool {
	for _, grafanaEmail := range grafanaTeamMemberEmails {
		if strings.EqualFold(email, grafanaEmail) {
			return true
		}
	}
	return false
}

func (r *grafanaReconciler) getOrCreateServiceAccount(ctx context.Context, teamName string) (int64, error) {
	params := &grafanaserviceaccounts.SearchOrgServiceAccountsWithPagingParams{
		Query:   &teamName,
		Context: ctx,
	}

	searchResp, err := r.serviceAccounts.SearchOrgServiceAccountsWithPaging(params)
	if err != nil {
		return 0, err
	}

	for _, serviceAccount := range searchResp.Payload.ServiceAccounts {
		if serviceAccount.Name == teamName {
			return serviceAccount.ID, nil
		}
	}

	createParams := &grafanaserviceaccounts.CreateServiceAccountParams{
		Body: &models.CreateServiceAccountForm{
			Name: teamName,
		},
		Context: ctx,
	}

	serviceAccount, err := r.serviceAccounts.CreateServiceAccount(createParams)
	if err != nil {
		return 0, err
	}

	return serviceAccount.GetPayload().ID, err
}

func (r *grafanaReconciler) setServiceAccountMembers(ctx context.Context, teamID int64, serviceAccountID int64) error {
	const resourceName = "serviceaccounts"

	existingPermissions, err := r.rbac.GetResourcePermissionsWithParams(&grafanaaccesscontrol.GetResourcePermissionsParams{
		Resource:   resourceName,
		ResourceID: strconv.Itoa(int(serviceAccountID)),
		Context:    ctx,
	})
	if err != nil {
		return err
	}

	// Revoke permissions from other teams/users and set permission to empty string to remove
	permissions := make([]*models.SetResourcePermissionCommand, 0)
	for _, existing := range existingPermissions.GetPayload() {
		if existing.TeamID != 0 && existing.TeamID != teamID {
			permissions = append(permissions, &models.SetResourcePermissionCommand{
				TeamID:     existing.TeamID,
				Permission: "",
			})
		} else if existing.UserID != 0 {
			permissions = append(permissions, &models.SetResourcePermissionCommand{
				UserID:     existing.UserID,
				Permission: "",
			})
		}
	}

	if len(permissions) > 0 || len(existingPermissions.GetPayload()) == 0 {
		permissions = append(permissions, &models.SetResourcePermissionCommand{
			Permission: "Edit",
			TeamID:     teamID,
		})

		_, err = r.rbac.SetResourcePermissions(&grafanaaccesscontrol.SetResourcePermissionsParams{
			Body: &models.SetPermissionsCommand{
				Permissions: permissions,
			},
			Resource:   resourceName,
			ResourceID: strconv.Itoa(int(serviceAccountID)),
			Context:    ctx,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *grafanaReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	environments, err := r.getTeamEnvironments(ctx, client, naisTeam.Slug)
	if err != nil {
		return fmt.Errorf("fetching team environments: %w", err)
	}

	teamID, err := r.getOrCreateTeam(ctx, naisTeam.Slug)
	if err != nil {
		return fmt.Errorf("getting or creating team: %w", err)
	}

	inPilot := naisTeam.Slug != "" && (slices.Contains(r.flags.GrafanaAlertPilotTeams, "*") || slices.Contains(r.flags.GrafanaAlertPilotTeams, naisTeam.Slug))
	if inPilot {
		log.Infof("Reconciling folder %s", naisTeam.Slug)
		folderUID, err := r.getOrCreateFolder(ctx, naisTeam.Slug)
		if err != nil {
			return fmt.Errorf("getting or creating folder: %w", err)
		}

		if err := r.setFolderTeamPermissions(ctx, folderUID, teamID); err != nil {
			return fmt.Errorf("setting folder team permissions: %w", err)
		}
	}

	members, err := r.getTeamMembers(ctx, client, naisTeam.Slug)
	if err != nil {
		return fmt.Errorf("fetching team members: %w", err)
	}

	grafanaUserIDMap := make(map[string]int64)
	for _, member := range members {
		userID, err := r.getOrCreateUser(ctx, member.GetUser())
		if err != nil {
			return fmt.Errorf("getting or creating user %s: %w", member.GetUser().GetEmail(), err)
		}
		grafanaUserIDMap[member.GetUser().GetEmail()] = userID
	}

	if err := r.syncTeamMembers(ctx, teamID, members, grafanaUserIDMap); err != nil {
		return fmt.Errorf("syncing team members: %w", err)
	}

	serviceAccountName := "team-" + naisTeam.Slug
	serviceAccountID, err := r.getOrCreateServiceAccount(ctx, serviceAccountName)
	if err != nil {
		return fmt.Errorf("getting or creating service account: %w", err)
	}

	if err := r.setServiceAccountMembers(ctx, teamID, serviceAccountID); err != nil {
		return fmt.Errorf("setting service account members: %w", err)
	}

	if r.flags.EnableGrafanaAlerts && inPilot {
		if err := r.reconcileAlerting(ctx, naisTeam.Slug, environments, log); err != nil {
			return fmt.Errorf("reconciling alerting: %w", err)
		}
	} else {
		log.Info("Grafana alerting is disabled or team is not in the alerting pilot, skipping alerting reconciliation")
	}

	return nil
}

func (r *grafanaReconciler) getTeamEnvironments(ctx context.Context, client *apiclient.APIClient, teamSlug string) ([]*protoapi.TeamEnvironment, error) {
	var environments []*protoapi.TeamEnvironment
	limit := int64(100)
	offset := int64(0)

	for {
		resp, err := client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{
			Slug:   teamSlug,
			Limit:  limit,
			Offset: offset,
		})
		if err != nil {
			return nil, err
		}

		environments = append(environments, resp.Nodes...)

		if len(resp.Nodes) < int(limit) {
			break
		}
		offset += limit
	}

	return environments, nil
}

func (r *grafanaReconciler) getTeamMembers(ctx context.Context, client *apiclient.APIClient, teamSlug string) ([]*protoapi.TeamMember, error) {
	var members []*protoapi.TeamMember
	limit := int64(100)
	offset := int64(0)

	for {
		resp, err := client.Teams().Members(ctx, &protoapi.ListTeamMembersRequest{
			Slug:   teamSlug,
			Limit:  limit,
			Offset: offset,
		})
		if err != nil {
			return nil, err
		}

		members = append(members, resp.Nodes...)

		if len(resp.Nodes) < int(limit) {
			break
		}
		offset += limit
	}

	return members, nil
}

func buildContactPointName(teamSlug, environmentName string) string {
	return fmt.Sprintf("team-%s-%s", teamSlug, environmentName)
}

func contactPointUID(name string) string {
	if len(name) <= 40 {
		return name
	}
	hash := sha256.Sum256([]byte(name))
	return fmt.Sprintf("team-%x", hash[:16])
}

func existingContactPointUID(points []*models.EmbeddedContactPoint, name, desiredUID string) (string, error) {
	var existing *models.EmbeddedContactPoint
	for _, point := range points {
		if point == nil || point.Name != name || point.UID == "" || len(point.UID) > 40 {
			return "", fmt.Errorf("invalid contact point returned for %q", name)
		}
		if point.UID == desiredUID {
			if existing != nil {
				return "", fmt.Errorf("duplicate contact point UID %q returned for %q", desiredUID, name)
			}
			existing = point
		}
	}
	if existing == nil {
		if len(points) != 1 {
			return "", fmt.Errorf("multiple integrations for contact point %q without expected UID %q; cannot determine which to update", name, desiredUID)
		}
		existing = points[0]
	}
	if existing.Type == nil || *existing.Type != contactPointType {
		return "", fmt.Errorf("contact point %q with UID %q is not a Slack integration", name, existing.UID)
	}
	return existing.UID, nil
}

func (r *grafanaReconciler) reconcileAlerting(ctx context.Context, teamSlug string, environments []*protoapi.TeamEnvironment, log logrus.FieldLogger) error {
	r.alertingMu.Lock()
	defer r.alertingMu.Unlock()

	baseline, _, err := r.notificationPolicyChanges(ctx, teamSlug, environments, log)
	if err != nil {
		return fmt.Errorf("checking notification policy routes: %w", err)
	}

	// Create notification templates first (only once, they're shared across all teams)
	if err := r.createNotificationTemplates(ctx); err != nil {
		return fmt.Errorf("creating notification templates: %w", err)
	}

	for _, env := range environments {
		if env.SlackAlertsChannel == "" {
			continue
		}

		contactPointName := buildContactPointName(teamSlug, env.EnvironmentName)
		if err := r.createOrUpdateContactPoint(ctx, contactPointName, env.SlackAlertsChannel, log); err != nil {
			return fmt.Errorf("creating contact point for %s-%s: %w", teamSlug, env.EnvironmentName, err)
		}
	}

	// Update notification routing policy to direct alerts to the correct contact points
	if err := r.updateNotificationPolicy(ctx, teamSlug, environments, baseline, log); err != nil {
		return fmt.Errorf("updating notification policy: %w", err)
	}

	return nil
}

func (r *grafanaReconciler) createOrUpdateContactPoint(ctx context.Context, name, slackChannel string, log logrus.FieldLogger) error {
	cpType := contactPointType

	contactPoint := &models.EmbeddedContactPoint{
		UID:      contactPointUID(name),
		Name:     name,
		Type:     &cpType,
		Settings: r.buildSlackContactPointSettings(slackChannel),
	}

	// Try to get existing contact point first
	getParams := &grafanaprovisioning.GetContactpointsParams{
		Name: &name,
	}
	getParams.SetContext(ctx)

	log.Debugf("Checking if contact point exists: %s", name)
	resp, err := r.provisioning.GetContactpoints(getParams)

	var operationErr error
	if err != nil {
		operationErr = fmt.Errorf("getting contact point %s: %w", name, err)
	} else if resp == nil {
		operationErr = fmt.Errorf("getting contact point %s: empty response", name)
	} else if len(resp.Payload) == 0 {
		// Contact point doesn't exist, create it
		log.Debugf("Contact point %s does not exist, creating with POST", name)
		createParams := &grafanaprovisioning.PostContactpointsParams{
			Body: contactPoint,
		}
		createParams.SetContext(ctx)

		_, operationErr = r.provisioning.PostContactpoints(createParams)
		if operationErr != nil {
			log.Debugf("POST contact point %s failed: %v", name, operationErr)
		} else {
			log.Debugf("POST contact point %s succeeded", name)
		}
	} else {
		uid, err := existingContactPointUID(resp.Payload, name, contactPoint.UID)
		if err != nil {
			operationErr = err
		} else {
			contactPoint.UID = uid
			log.Debugf("Contact point %s exists (UID %s), updating with PUT", name, uid)
			updateParams := &grafanaprovisioning.PutContactpointParams{
				UID:  uid,
				Body: contactPoint,
			}
			updateParams.SetContext(ctx)

			_, operationErr = r.provisioning.PutContactpoint(updateParams)
			if operationErr != nil {
				log.Debugf("PUT contact point %s failed: %v", name, operationErr)
			} else {
				log.Debugf("PUT contact point %s succeeded", name)
			}
		}
	}

	// Record metrics
	if operationErr != nil {
		r.metricContactPointsFailed.Add(ctx, 1, metric.WithAttributes(
			attribute.String("contact_point_name", name),
			attribute.String("slack_channel", slackChannel),
		))
	} else {
		r.metricContactPointsCreated.Add(ctx, 1, metric.WithAttributes(
			attribute.String("contact_point_name", name),
			attribute.String("slack_channel", slackChannel),
		))
	}

	return operationErr
}

func (r *grafanaReconciler) updateNotificationPolicy(ctx context.Context, teamSlug string, environments []*protoapi.TeamEnvironment, baseline *models.Route, log logrus.FieldLogger) error {
	policyTree, newRoutes, err := r.notificationPolicyChanges(ctx, teamSlug, environments, log)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(policyTree, baseline) {
		return fmt.Errorf("notification policy tree changed since preflight for team %s; refusing to overwrite external changes", teamSlug)
	}
	if err := r.ensureDiscardMuteTiming(ctx); err != nil {
		return err
	}
	if len(newRoutes) == 0 && policyTree.Provenance != "" {
		return nil
	}
	latest, err := r.provisioning.GetPolicyTree()
	if err != nil {
		return fmt.Errorf("rechecking policy tree after ensuring discard mute timing: %w", err)
	}
	if latest == nil || latest.Payload == nil {
		return fmt.Errorf("rechecking policy tree after ensuring discard mute timing: empty response")
	}
	if !reflect.DeepEqual(latest.Payload, baseline) {
		return fmt.Errorf("notification policy tree changed while ensuring discard mute timing for team %s; refusing to overwrite external changes", teamSlug)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if len(newRoutes) != 0 {
		policyTree.Routes = newRoutes
	}

	r.metricPolicyTreeSize.Record(ctx, int64(len(policyTree.Routes)), metric.WithAttributes(
		attribute.String("operation", "write"),
		attribute.String("team", teamSlug),
	))

	params := &grafanaprovisioning.PutPolicyTreeParams{
		Body: policyTree,
	}
	params.SetContext(ctx)

	_, err = r.provisioning.PutPolicyTree(params)
	if err != nil {
		r.metricPolicyTreeUpdatesFailed.Add(ctx, 1, metric.WithAttributes(
			attribute.String("team", teamSlug),
		))
		return fmt.Errorf("updating policy tree: %w", err)
	}
	r.metricPolicyTreeUpdates.Add(ctx, 1, metric.WithAttributes(
		attribute.String("team", teamSlug),
	))

	return nil
}

func (r *grafanaReconciler) notificationPolicyChanges(ctx context.Context, teamSlug string, environments []*protoapi.TeamEnvironment, log logrus.FieldLogger) (*models.Route, []*models.Route, error) {
	if teamSlug == "" {
		return nil, nil, fmt.Errorf("cannot reconcile notification policies without a team slug")
	}
	for _, env := range environments {
		if env == nil || (env.SlackAlertsChannel != "" && env.EnvironmentName == "") {
			return nil, nil, fmt.Errorf("team %s has an invalid alerting environment", teamSlug)
		}
	}
	resp, err := r.provisioning.GetPolicyTree()
	if err != nil {
		return nil, nil, fmt.Errorf("getting policy tree: %w", err)
	}
	if resp == nil || resp.Payload == nil {
		return nil, nil, fmt.Errorf("getting policy tree: empty response")
	}

	policyTree := resp.Payload
	matches, err := routeMatchesTeam(policyTree, teamSlug)
	if err != nil {
		return nil, nil, err
	}
	if matches {
		return nil, nil, fmt.Errorf("root notification route for team %s requires manual migration", teamSlug)
	}
	r.metricPolicyTreeSize.Record(ctx, int64(len(policyTree.Routes)), metric.WithAttributes(
		attribute.String("operation", "read"),
		attribute.String("team", teamSlug),
	))

	desired := r.buildNotificationRoutes(teamSlug, environments, log)
	for _, route := range desired {
		if policyTree.Receiver == route.Receiver {
			return nil, nil, fmt.Errorf("contact point %q is already used by the root notification route", route.Receiver)
		}
	}
	additions, err := planTeamNotificationRoutes(policyTree.Routes, desired, teamSlug)
	if err != nil {
		return nil, nil, err
	}
	return policyTree, additions, nil
}

func (r *grafanaReconciler) ensureDiscardMuteTiming(ctx context.Context) error {
	desired := &models.MuteTimeInterval{
		Name: discardMuteTiming,
		TimeIntervals: []*models.TimeIntervalItem{{
			Times: []*models.TimeIntervalTimeRange{{StartTime: "00:00", EndTime: "24:00"}},
		}},
	}
	resp, err := r.provisioning.GetMuteTimingsWithParams(grafanaprovisioning.NewGetMuteTimingsParamsWithContext(ctx))
	if err != nil {
		return fmt.Errorf("getting discard mute timing: %w", err)
	}
	if resp == nil {
		return fmt.Errorf("getting discard mute timing: empty response")
	}
	for _, timing := range resp.Payload {
		if timing == nil {
			return fmt.Errorf("getting discard mute timing: null interval")
		}
		if timing.Name == desired.Name {
			if len(timing.TimeIntervals) != 1 || timing.TimeIntervals[0] == nil {
				return fmt.Errorf("mute timing %q differs from the always-muted fallback; requires manual migration", desired.Name)
			}
			interval := timing.TimeIntervals[0]
			if len(interval.DaysOfMonth) != 0 || len(interval.Months) != 0 ||
				len(interval.Weekdays) != 0 || len(interval.Years) != 0 ||
				len(interval.Times) != 1 || interval.Times[0] == nil ||
				interval.Times[0].StartTime != "00:00" || interval.Times[0].EndTime != "24:00" {
				return fmt.Errorf("mute timing %q differs from the always-muted fallback; requires manual migration", desired.Name)
			}
			return nil
		}
	}
	created, err := r.provisioning.PostMuteTiming(&grafanaprovisioning.PostMuteTimingParams{
		Body: desired, Context: ctx,
	})
	if err != nil {
		return fmt.Errorf("creating discard mute timing: %w", err)
	}
	if created == nil {
		return fmt.Errorf("creating discard mute timing: empty response")
	}
	return nil
}

func planTeamNotificationRoutes(existing, desired []*models.Route, teamSlug string) ([]*models.Route, error) {
	parent := &models.Route{ObjectMatchers: models.ObjectMatchers{{"team", "=", teamSlug}}}
	fallback := &models.Route{MuteTimeIntervals: []string{discardMuteTiming}}
	expected := make(map[string]*models.Route, len(desired))
	for _, route := range desired {
		if expected[route.Receiver] != nil {
			return nil, fmt.Errorf("duplicate notification route for contact point %s", route.Receiver)
		}
		child := *route
		child.ObjectMatchers = nil
		for _, matcher := range route.ObjectMatchers {
			if matcher[0] != "team" {
				child.ObjectMatchers = append(child.ObjectMatchers, matcher)
			}
		}
		expected[route.Receiver] = &child
	}

	parentIndex := -1
	var unrelated []*models.Route
	for i, route := range existing {
		if route == nil {
			return nil, fmt.Errorf("nil notification route in policy tree")
		}
		shell := *route
		shell.Routes = nil
		if sameNotificationRoute(&shell, parent) {
			if parentIndex != -1 {
				return nil, fmt.Errorf("duplicate team parent for %s requires manual migration", teamSlug)
			}
			parentIndex = i
		} else {
			unrelated = append(unrelated, route)
		}
	}
	if parentIndex != -1 {
		additions, err := routesToAdd(unrelated, desired, teamSlug)
		if err != nil {
			return nil, err
		}
		if len(additions) != len(desired) {
			return nil, fmt.Errorf("mixed flat and nested notification routes for team %s require manual migration", teamSlug)
		}
		current := existing[parentIndex]
		seen := make(map[string]bool, len(expected))
		if len(current.Routes) == 0 || current.Routes[len(current.Routes)-1] == nil ||
			!sameNotificationRoute(current.Routes[len(current.Routes)-1], fallback) {
			return nil, fmt.Errorf("team %s fallback requires manual migration", teamSlug)
		}
		for _, child := range current.Routes[:len(current.Routes)-1] {
			if child == nil || expected[child.Receiver] == nil ||
				!sameNotificationRoute(child, expected[child.Receiver]) || seen[child.Receiver] {
				return nil, fmt.Errorf("team %s environment route requires manual migration", teamSlug)
			}
			seen[child.Receiver] = true
			parent.Routes = append(parent.Routes, child)
		}
		for _, route := range desired {
			if !seen[route.Receiver] {
				parent.Routes = append(parent.Routes, expected[route.Receiver])
			}
		}
		parent.Routes = append(parent.Routes, fallback)
		if len(seen) == len(desired) {
			return nil, nil
		}
		planned := slices.Clone(existing)
		planned[parentIndex] = parent
		return planned, nil
	}

	if _, err := routesToAdd(existing, desired, teamSlug); err != nil {
		return nil, err
	}
	for _, route := range desired {
		parent.Routes = append(parent.Routes, expected[route.Receiver])
	}
	parent.Routes = append(parent.Routes, fallback)
	var planned []*models.Route
	inserted, interrupted := false, false
	for _, route := range existing {
		matches, err := routeMatchesTeam(route, teamSlug)
		if err != nil {
			return nil, err
		}
		if matches {
			if interrupted {
				return nil, fmt.Errorf("interleaved notification routes for team %s require manual migration", teamSlug)
			}
			if !inserted {
				planned = append(planned, parent)
				inserted = true
			}
		} else {
			planned = append(planned, route)
			if inserted {
				interrupted = true
			}
		}
	}
	if !inserted {
		planned = append(planned, parent)
	}
	return planned, nil
}

func routesToAdd(existing, desired []*models.Route, teamSlug string) ([]*models.Route, error) {
	expected := make(map[string]*models.Route, len(desired))
	for _, route := range desired {
		if _, ok := expected[route.Receiver]; ok {
			return nil, fmt.Errorf("duplicate notification route for contact point %s", route.Receiver)
		}
		expected[route.Receiver] = route
	}

	seen := make(map[string]bool, len(desired))
	for _, route := range existing {
		if route == nil {
			return nil, fmt.Errorf("nil notification route in policy tree")
		}
		matches, err := routeMatchesTeam(route, teamSlug)
		if err != nil {
			return nil, err
		}
		if matches {
			want, ok := expected[route.Receiver]
			if !ok || !sameNotificationRoute(route, want) || seen[route.Receiver] {
				return nil, fmt.Errorf("existing notification route for team %s (receiver %q) requires manual migration", teamSlug, route.Receiver)
			}
			seen[route.Receiver] = true
		} else if expected[route.Receiver] != nil {
			return nil, fmt.Errorf("contact point %q is already used by another notification route", route.Receiver)
		}
		if err := checkNestedTeamRoutes(route.Routes, teamSlug, expected); err != nil {
			return nil, err
		}
	}

	var additions []*models.Route
	for _, route := range desired {
		if !seen[route.Receiver] {
			additions = append(additions, route)
		}
	}
	return additions, nil
}

func checkNestedTeamRoutes(routes []*models.Route, teamSlug string, expected map[string]*models.Route) error {
	for _, route := range routes {
		if route == nil {
			return fmt.Errorf("nil nested notification route in policy tree")
		}
		matches, err := routeMatchesTeam(route, teamSlug)
		if err != nil {
			return err
		}
		if matches {
			return fmt.Errorf("nested notification route for team %s (receiver %q) requires manual migration", teamSlug, route.Receiver)
		}
		if expected[route.Receiver] != nil {
			return fmt.Errorf("contact point %q is already used by a nested notification route", route.Receiver)
		}
		if err := checkNestedTeamRoutes(route.Routes, teamSlug, expected); err != nil {
			return err
		}
	}
	return nil
}

func sameNotificationRoute(route, want *models.Route) bool {
	if route.Receiver != want.Receiver || route.Continue || len(route.Routes) != 0 ||
		len(route.Match) != 0 || len(route.MatchRe) != 0 || len(route.Matchers) != 0 ||
		!slices.Equal(route.MuteTimeIntervals, want.MuteTimeIntervals) || !slices.Equal(route.ActiveTimeIntervals, want.ActiveTimeIntervals) ||
		route.GroupWait != want.GroupWait || route.GroupInterval != want.GroupInterval ||
		route.RepeatInterval != want.RepeatInterval || !slices.Equal(route.GroupBy, want.GroupBy) ||
		len(route.ObjectMatchers) != len(want.ObjectMatchers) {
		return false
	}
	for _, matcher := range want.ObjectMatchers {
		found := false
		for _, existing := range route.ObjectMatchers {
			if slices.Equal(existing, matcher) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func routeMatchesTeam(route *models.Route, teamSlug string) (bool, error) {
	hasTeamMatcher, matchesTeam := false, true
	if value, ok := route.Match["team"]; ok {
		hasTeamMatcher = true
		matchesTeam = value == teamSlug
	}
	if pattern, ok := route.MatchRe["team"]; ok {
		hasTeamMatcher = true
		matches, err := teamRegexMatches(pattern, teamSlug)
		if err != nil {
			return false, err
		}
		matchesTeam = matchesTeam && matches
	}
	for _, matcher := range route.Matchers {
		if matcher == nil || matcher.Name == "" {
			return false, fmt.Errorf("invalid notification route matcher")
		}
		if matcher.Name != "team" {
			continue
		}
		hasTeamMatcher = true
		matches, err := teamMatcherApplies(matcher.Type, matcher.Value, teamSlug)
		if err != nil {
			return false, err
		}
		matchesTeam = matchesTeam && matches
	}
	for _, matcher := range route.ObjectMatchers {
		if len(matcher) == 0 || matcher[0] != "team" {
			continue
		}
		if len(matcher) != 3 {
			return false, fmt.Errorf("invalid team matcher in notification route")
		}
		hasTeamMatcher = true
		var matches bool
		switch matcher[1] {
		case "=":
			matches = matcher[2] == teamSlug
		case "!=":
			matches = matcher[2] != teamSlug
		case "=~", "!~":
			regexMatches, err := teamRegexMatches(matcher[2], teamSlug)
			if err != nil {
				return false, err
			}
			matches = regexMatches == (matcher[1] == "=~")
		default:
			return false, fmt.Errorf("unsupported team matcher operator %q", matcher[1])
		}
		matchesTeam = matchesTeam && matches
	}
	return hasTeamMatcher && matchesTeam, nil
}

// Match types follow the Alertmanager labels.MatchType enum.
const (
	matchEqual models.MatchType = iota
	matchNotEqual
	matchRegexp
	matchNotRegexp
)

func teamMatcherApplies(matchType models.MatchType, value, teamSlug string) (bool, error) {
	switch matchType {
	case matchEqual:
		return value == teamSlug, nil
	case matchNotEqual:
		return value != teamSlug, nil
	case matchRegexp, matchNotRegexp:
		matches, err := teamRegexMatches(value, teamSlug)
		if err != nil {
			return false, err
		}
		return matches == (matchType == matchRegexp), nil
	default:
		return false, fmt.Errorf("unsupported team matcher type %d", matchType)
	}
}

func teamRegexMatches(pattern, teamSlug string) (bool, error) {
	matches, err := regexp.MatchString("^(?:"+pattern+")$", teamSlug)
	if err != nil {
		return false, fmt.Errorf("invalid team matcher %q: %w", pattern, err)
	}
	return matches, nil
}

func (r *grafanaReconciler) buildNotificationRoutes(teamSlug string, environments []*protoapi.TeamEnvironment, log logrus.FieldLogger) []*models.Route {
	var routes []*models.Route

	for _, env := range environments {
		if env.SlackAlertsChannel == "" {
			continue
		}

		route := buildEnvironmentNotificationRoute(teamSlug, env.EnvironmentName)

		// Debug: Log what we're creating
		log.Debugf("Creating route - Receiver: %s, Team: %s, Environment: %s",
			route.Receiver, teamSlug, env.EnvironmentName)
		log.Debugf("Route details - ObjectMatchers: %+v, GroupBy: %+v",
			route.ObjectMatchers, route.GroupBy)

		routes = append(routes, route)
	}

	return routes
}

func buildEnvironmentNotificationRoute(teamSlug, environmentName string) *models.Route {
	return &models.Route{
		Receiver: buildContactPointName(teamSlug, environmentName),
		ObjectMatchers: models.ObjectMatchers{
			{"team", "=", teamSlug},
			{"env", "=", environmentName},
		},
		GroupBy:        []string{"alertname", "team", "env"},
		GroupWait:      defaultGroupWait,
		GroupInterval:  defaultGroupInterval,
		RepeatInterval: defaultRepeatInterval,
	}
}

func createSecurePassword() string {
	randomData := make([]byte, 32)
	_, err := rand.Read(randomData)
	if err != nil {
		panic("not enough entropy")
	}

	return base64.StdEncoding.EncodeToString(randomData)
}
