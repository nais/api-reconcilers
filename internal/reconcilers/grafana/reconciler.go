package grafana_reconciler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/nais/api-reconcilers/internal/cmd/reconciler/config"
	"github.com/nais/api-reconcilers/internal/reconcilers"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"

	grafana_accesscontrol "github.com/grafana/grafana-openapi-client-go/client/access_control"
	grafana_admin_users "github.com/grafana/grafana-openapi-client-go/client/admin_users"
	grafana_provisioning "github.com/grafana/grafana-openapi-client-go/client/provisioning"
	grafana_serviceaccounts "github.com/grafana/grafana-openapi-client-go/client/service_accounts"
	grafana_teams "github.com/grafana/grafana-openapi-client-go/client/teams"
	grafana_users "github.com/grafana/grafana-openapi-client-go/client/users"
	"github.com/grafana/grafana-openapi-client-go/models"
)

const (
	grafanaReconcilerName = "grafana"

	// Contact point and notification policy settings
	contactPointType = "slack"

	// Default notification timing settings
	defaultGroupWait      = "10s"
	defaultGroupInterval  = "5m"
	defaultRepeatInterval = "12h"
)

type grafanaReconciler struct {
	users           grafana_users.ClientService
	teams           grafana_teams.ClientService
	rbac            grafana_accesscontrol.ClientService
	serviceAccounts grafana_serviceaccounts.ClientService
	adminUsers      grafana_admin_users.ClientService
	provisioning    grafana_provisioning.ClientService
	flags           config.FeatureFlags
}

func New(
	users grafana_users.ClientService,
	teams grafana_teams.ClientService,
	rbac grafana_accesscontrol.ClientService,
	serviceAccounts grafana_serviceaccounts.ClientService,
	adminUsers grafana_admin_users.ClientService,
	provisioning grafana_provisioning.ClientService,
	flags config.FeatureFlags,
) reconcilers.Reconciler {
	return &grafanaReconciler{
		users:           users,
		teams:           teams,
		rbac:            rbac,
		serviceAccounts: serviceAccounts,
		adminUsers:      adminUsers,
		provisioning:    provisioning,
		flags:           flags,
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

func (r *grafanaReconciler) getOrCreateTeam(ctx context.Context, teamName string) (int64, error) {
	params := &grafana_teams.SearchTeamsParams{
		Query:   &teamName,
		Context: ctx,
	}

	searchResp, err := r.teams.SearchTeams(params)
	if err != nil {
		return 0, err
	}

	for _, team := range searchResp.Payload.Teams {
		if team.Name == teamName {
			return team.ID, nil
		}
	}

	createResp, err := r.teams.CreateTeamWithParams(&grafana_teams.CreateTeamParams{
		Body: &models.CreateTeamCommand{
			Name: teamName,
		},
		Context: ctx,
	})
	if err != nil {
		return 0, err
	}

	return createResp.Payload.TeamID, nil
}

func (r *grafanaReconciler) getOrCreateUser(ctx context.Context, user *protoapi.User) (int64, error) {
	existingUser, err := r.users.GetUserByLoginOrEmailWithParams(&grafana_users.GetUserByLoginOrEmailParams{
		LoginOrEmail: user.GetEmail(),
		Context:      ctx,
	})
	if err == nil {
		return existingUser.GetPayload().ID, nil
	}

	newUser, err := r.adminUsers.AdminCreateUserWithParams(&grafana_admin_users.AdminCreateUserParams{
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

// Make sure the Grafana team contains exactly the set of users from the nais team.
func (r *grafanaReconciler) syncTeamMembers(ctx context.Context, teamID int64, naisTeamMembers []*protoapi.TeamMember, grafanaUserIDMap map[string]int64) error {
	teamIDString := strconv.Itoa(int(teamID))
	grafanaExistingMembers, err := r.teams.GetTeamMembersWithParams(&grafana_teams.GetTeamMembersParams{
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
		_, err = r.teams.RemoveTeamMemberWithParams(&grafana_teams.RemoveTeamMemberParams{
			TeamID:  teamIDString,
			UserID:  userID,
			Context: ctx,
		})
		if err != nil {
			return err
		}
	}

	for _, email := range membersToAdd {
		_, err = r.teams.AddTeamMemberWithParams(&grafana_teams.AddTeamMemberParams{
			Body: &models.AddTeamMemberCommand{
				UserID: grafanaUserIDMap[email],
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

// Create a service account if it doesn't exist, or return the ID of the existing one.
func (r *grafanaReconciler) getOrCreateServiceAccount(ctx context.Context, teamName string) (int64, error) {
	params := &grafana_serviceaccounts.SearchOrgServiceAccountsWithPagingParams{
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

	createParams := &grafana_serviceaccounts.CreateServiceAccountParams{
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

// Ensure that only our team has permissions granted to the service account.
func (r *grafanaReconciler) setServiceAccountMembers(ctx context.Context, teamID int64, serviceAccountID int64) error {
	const resourceName = "serviceaccounts"

	existingPermissions, err := r.rbac.GetResourcePermissionsWithParams(&grafana_accesscontrol.GetResourcePermissionsParams{
		Resource:   resourceName,
		ResourceID: strconv.Itoa(int(serviceAccountID)),
		Context:    ctx,
	})
	if err != nil {
		return err
	}

	// Revoke all existing permissions that doesn't match the nais team.
	// Also applies to any users that were manually added.
	// Revoking is done by setting the permission to an empty string.
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
		// Make sure our nais team has editor permissions.
		permissions = append(permissions, &models.SetResourcePermissionCommand{
			Permission: "Edit",
			TeamID:     teamID,
		})

		// apply the changes.
		_, err = r.rbac.SetResourcePermissions(&grafana_accesscontrol.SetResourcePermissionsParams{
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
	// Fetch team environments to get Slack alert channels
	environments, err := r.getTeamEnvironments(ctx, client, naisTeam.Slug)
	if err != nil {
		return fmt.Errorf("fetching team environments: %w", err)
	}

	// Check if team exists in Grafana, otherwise create it. Keep the ID.
	teamID, err := r.getOrCreateTeam(ctx, naisTeam.Slug)
	if err != nil {
		return fmt.Errorf("getting or creating team: %w", err)
	}

	// Get team members from the API
	members, err := r.getTeamMembers(ctx, client, naisTeam.Slug)
	if err != nil {
		return fmt.Errorf("fetching team members: %w", err)
	}

	// Check if all users exist in Grafana, otherwise create them and set a random password. Keep the user IDs.
	grafanaUserIDMap := make(map[string]int64)
	for _, member := range members {
		userID, err := r.getOrCreateUser(ctx, member.GetUser())
		if err != nil {
			return fmt.Errorf("getting or creating user %s: %w", member.GetUser().GetEmail(), err)
		}
		grafanaUserIDMap[member.GetUser().GetEmail()] = userID
	}

	// Make sure memberships are exactly equal in Grafana and local dataset.
	if err := r.syncTeamMembers(ctx, teamID, members, grafanaUserIDMap); err != nil {
		return fmt.Errorf("syncing team members: %w", err)
	}

	// Check if the service account exists in Grafana, otherwise create it.
	serviceAccountName := "team-" + naisTeam.Slug
	serviceAccountID, err := r.getOrCreateServiceAccount(ctx, serviceAccountName)
	if err != nil {
		return fmt.Errorf("getting or creating service account: %w", err)
	}

	// Add the team to the service account with "Edit" permissions.
	if err := r.setServiceAccountMembers(ctx, teamID, serviceAccountID); err != nil {
		return fmt.Errorf("setting service account members: %w", err)
	}

	// Create or update contact points and notification policies for each environment
	if r.flags.EnableGrafanaAlerts {
		if err := r.reconcileAlerting(ctx, naisTeam.Slug, environments); err != nil {
			return fmt.Errorf("reconciling alerting: %w", err)
		}
	} else {
		log.Info("Grafana alerting is disabled, skipping alerting reconciliation")
	}

	return nil
}

// getTeamEnvironments fetches all environments for a team
func (r *grafanaReconciler) getTeamEnvironments(ctx context.Context, client *apiclient.APIClient, teamSlug string) ([]*protoapi.TeamEnvironment, error) {
	var environments []*protoapi.TeamEnvironment

	// Use pagination to get all environments
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

// getTeamMembers fetches all members for a team
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

// buildContactPointName creates a standardized contact point name for team-environment combinations.
func (r *grafanaReconciler) buildContactPointName(teamSlug, environmentName string) string {
	return fmt.Sprintf("team-%s-%s", teamSlug, environmentName)
}

// reconcileAlerting creates or updates Grafana contact points and notification policies for team environments.
// For each environment with a configured Slack alerts channel, this method:
// 1. Creates/updates a Slack contact point with the team-environment naming pattern
// 2. Updates the notification policy tree to route alerts to the appropriate contact points
func (r *grafanaReconciler) reconcileAlerting(ctx context.Context, teamSlug string, environments []*protoapi.TeamEnvironment) error {
	// Create contact points for environments that have Slack alerts configured
	for _, env := range environments {
		if env.SlackAlertsChannel == "" {
			continue
		}

		contactPointName := r.buildContactPointName(teamSlug, env.EnvironmentName)
		if err := r.createOrUpdateContactPoint(ctx, contactPointName, env.SlackAlertsChannel); err != nil {
			return fmt.Errorf("creating contact point for %s-%s: %w", teamSlug, env.EnvironmentName, err)
		}
	}

	// Update notification routing policy to direct alerts to the correct contact points
	if err := r.updateNotificationPolicy(ctx, teamSlug, environments); err != nil {
		return fmt.Errorf("updating notification policy: %w", err)
	}

	return nil
}

// createOrUpdateContactPoint creates or updates a Slack contact point in Grafana.
// The contact point is configured with:
// - Standardized message formatting including team and environment labels
// - Conditional coloring based on alert status (firing/resolved)
// - Uses the contact point name as UID for idempotent operations
func (r *grafanaReconciler) createOrUpdateContactPoint(ctx context.Context, name, slackChannel string) error {
	cpType := contactPointType

	contactPoint := &models.EmbeddedContactPoint{
		UID:  name, // Use name as UID for idempotency
		Type: &cpType,
		Settings: map[string]interface{}{
			"channel":   slackChannel,
			"title":     "Alert: {{.GroupLabels.alertname}}",
			"text":      "Team: {{.GroupLabels.team}} | Environment: {{.GroupLabels.environment}}\n{{range .Alerts}}{{.Annotations.summary}}\n{{.Annotations.description}}{{end}}",
			"username":  "Grafana",
			"iconEmoji": ":exclamation:",
			"iconURL":   "",
			"color":     "{{if eq .Status \"firing\"}}danger{{else}}good{{end}}",
		},
	}

	params := &grafana_provisioning.PutContactpointParams{
		UID:  name,
		Body: contactPoint,
	}
	params.SetContext(ctx)

	_, err := r.provisioning.PutContactpoint(params)
	return err
}

// updateNotificationPolicy updates the Grafana notification routing policy tree.
// This method:
// 1. Fetches the current policy tree
// 2. Removes any existing routes for the team to prevent duplicates
// 3. Adds new routes for each environment with Slack alerts configured
// 4. Updates the policy tree atomically
func (r *grafanaReconciler) updateNotificationPolicy(ctx context.Context, teamSlug string, environments []*protoapi.TeamEnvironment) error {
	resp, err := r.provisioning.GetPolicyTree()
	if err != nil {
		return fmt.Errorf("getting policy tree: %w", err)
	}

	policyTree := resp.Payload
	if policyTree.Routes == nil {
		policyTree.Routes = []*models.Route{}
	}

	// Remove existing routes for this team to ensure idempotent behavior
	filteredRoutes := r.filterRoutesForTeam(policyTree.Routes, teamSlug)

	// Create new routes for environments with Slack alerts configured
	newRoutes := r.buildNotificationRoutes(teamSlug, environments)
	filteredRoutes = append(filteredRoutes, newRoutes...)

	policyTree.Routes = filteredRoutes

	// Apply the updated policy tree
	params := &grafana_provisioning.PutPolicyTreeParams{
		Body: policyTree,
	}
	params.SetContext(ctx)

	_, err = r.provisioning.PutPolicyTree(params)
	if err != nil {
		return fmt.Errorf("updating policy tree: %w", err)
	}

	return nil
}

// filterRoutesForTeam returns all routes that do not belong to the specified team.
func (r *grafanaReconciler) filterRoutesForTeam(routes []*models.Route, teamSlug string) []*models.Route {
	var filteredRoutes []*models.Route
	for _, route := range routes {
		if !r.isRouteForTeam(route, teamSlug) {
			filteredRoutes = append(filteredRoutes, route)
		}
	}
	return filteredRoutes
}

// buildNotificationRoutes creates notification routes for environments with Slack alerts configured.
func (r *grafanaReconciler) buildNotificationRoutes(teamSlug string, environments []*protoapi.TeamEnvironment) []*models.Route {
	var routes []*models.Route

	for _, env := range environments {
		if env.SlackAlertsChannel == "" {
			continue
		}

		contactPointName := r.buildContactPointName(teamSlug, env.EnvironmentName)

		// Create label matchers for team and environment
		teamMatcher := models.ObjectMatcher{"team", "=", teamSlug}
		envMatcher := models.ObjectMatcher{"environment", "=", env.EnvironmentName}

		route := &models.Route{
			Receiver:       contactPointName,
			ObjectMatchers: models.ObjectMatchers{teamMatcher, envMatcher},
			Continue:       false, // Stop processing after this route matches
			GroupBy:        []string{"alertname", "team", "environment"},
			GroupWait:      defaultGroupWait,
			GroupInterval:  defaultGroupInterval,
			RepeatInterval: defaultRepeatInterval,
		}

		routes = append(routes, route)
	}

	return routes
}

// isRouteForTeam checks if a notification route belongs to the specified team.
// A route belongs to a team if it has an ObjectMatcher with label "team" and the team slug as value.
func (r *grafanaReconciler) isRouteForTeam(route *models.Route, teamSlug string) bool {
	if route.ObjectMatchers == nil {
		return false
	}

	for _, matcher := range route.ObjectMatchers {
		if len(matcher) >= 3 && matcher[0] == "team" && matcher[2] == teamSlug {
			return true
		}
	}

	return false
}

// Delete removes a team and its associated resources from Grafana.
// This method performs the following cleanup operations:
// 1. Removes alerting configuration (notification routes) if provisioning service is available
// 2. Deletes the Grafana team
// Note: Grafana automatically handles cleanup of dangling references to the deleted team.
func (r *grafanaReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	teamName := naisTeam.GetSlug()

	// Clean up alerting configuration first (only if provisioning service is available)
	if r.provisioning != nil {
		if err := r.cleanupAlerting(ctx, teamName); err != nil {
			log.WithError(err).Warn("Failed to cleanup alerting configuration")
		}
	}

	// Find and delete the Grafana team
	params := &grafana_teams.SearchTeamsParams{
		Query:   &teamName,
		Context: ctx,
	}

	searchResp, err := r.teams.SearchTeams(params)
	if err != nil {
		return err
	}

	for _, team := range searchResp.Payload.Teams {
		if team.Name == teamName {
			_, err = r.teams.DeleteTeamByID(strconv.Itoa(int(team.ID)))
			if err != nil {
				return err
			}
			return nil
		}
	}

	return nil
}

// cleanupAlerting removes notification routes for a deleted team.
// This method:
// 1. Fetches the current notification policy tree
// 2. Filters out all routes belonging to the team
// 3. Updates the policy tree with the filtered routes
// Note: Contact point cleanup is not implemented as it requires additional API calls.
// Contact points follow the naming pattern: team-{teamSlug}-{envName}
func (r *grafanaReconciler) cleanupAlerting(ctx context.Context, teamSlug string) error {
	resp, err := r.provisioning.GetPolicyTree()
	if err != nil {
		return fmt.Errorf("getting policy tree: %w", err)
	}

	policyTree := resp.Payload
	if policyTree.Routes != nil {
		// Remove all routes for this team
		policyTree.Routes = r.filterRoutesForTeam(policyTree.Routes, teamSlug)

		// Apply the updated policy tree
		params := &grafana_provisioning.PutPolicyTreeParams{
			Body: policyTree,
		}
		params.SetContext(ctx)

		_, err = r.provisioning.PutPolicyTree(params)
		if err != nil {
			return fmt.Errorf("updating policy tree during cleanup: %w", err)
		}
	}

	return nil
}

// Generate a random password with 256 bits of entropy.
func createSecurePassword() string {
	randomData := make([]byte, 32)
	_, err := rand.Read(randomData)
	if err != nil {
		panic("not enough entropy")
	}

	return base64.StdEncoding.EncodeToString(randomData)
}
