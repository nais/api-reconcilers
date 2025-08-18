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

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	grafanaReconcilerName = "grafana"
	contactPointType      = "slack"

	// Timing settings optimized for immediate grouping with reasonable repeat intervals
	defaultGroupWait      = "0s"
	defaultGroupInterval  = "5m"
	defaultRepeatInterval = "3h"

	defaultSlackUsername = "Grafana"
)

type grafanaReconciler struct {
	users           grafana_users.ClientService
	teams           grafana_teams.ClientService
	rbac            grafana_accesscontrol.ClientService
	serviceAccounts grafana_serviceaccounts.ClientService
	adminUsers      grafana_admin_users.ClientService
	provisioning    grafana_provisioning.ClientService
	flags           config.FeatureFlags
	slackWebhookURL string

	// Metrics for monitoring Grafana reconciler performance
	metricContactPointsCreated    metric.Int64Counter
	metricContactPointsFailed     metric.Int64Counter
	metricPolicyTreeSize          metric.Int64Gauge
	metricPolicyTreeUpdates       metric.Int64Counter
	metricPolicyTreeUpdatesFailed metric.Int64Counter
}

func New(
	users grafana_users.ClientService,
	teams grafana_teams.ClientService,
	rbac grafana_accesscontrol.ClientService,
	serviceAccounts grafana_serviceaccounts.ClientService,
	adminUsers grafana_admin_users.ClientService,
	provisioning grafana_provisioning.ClientService,
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
		users:           users,
		teams:           teams,
		rbac:            rbac,
		serviceAccounts: serviceAccounts,
		adminUsers:      adminUsers,
		provisioning:    provisioning,
		flags:           flags,
		slackWebhookURL: slackWebhookURL,

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

func (r *grafanaReconciler) buildSlackContactPointSettings(slackChannel string) map[string]interface{} {
	return map[string]interface{}{
		"recipient":  slackChannel,
		"username":   defaultSlackUsername,
		"icon_emoji": ":grafana:",
		"color":      "{{ if eq .Status \"firing\" }}#D63232{{ else }}#36a64f{{ end }}",
		"title":      "{{ template \"slack.default.title\" . }}",
		"text":       "{{ template \"slack.default.text\" . }}",
		"url":        r.slackWebhookURL,
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
	environments, err := r.getTeamEnvironments(ctx, client, naisTeam.Slug)
	if err != nil {
		return fmt.Errorf("fetching team environments: %w", err)
	}

	teamID, err := r.getOrCreateTeam(ctx, naisTeam.Slug)
	if err != nil {
		return fmt.Errorf("getting or creating team: %w", err)
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

	if r.flags.EnableGrafanaAlerts {
		if err := r.reconcileAlerting(ctx, naisTeam.Slug, environments); err != nil {
			return fmt.Errorf("reconciling alerting: %w", err)
		}
	} else {
		log.Info("Grafana alerting is disabled, skipping alerting reconciliation")
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

func (r *grafanaReconciler) buildContactPointName(teamSlug, environmentName string) string {
	return fmt.Sprintf("team-%s-%s", teamSlug, environmentName)
}

func (r *grafanaReconciler) reconcileAlerting(ctx context.Context, teamSlug string, environments []*protoapi.TeamEnvironment) error {
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

func (r *grafanaReconciler) createOrUpdateContactPoint(ctx context.Context, name, slackChannel string) error {
	cpType := contactPointType

	contactPoint := &models.EmbeddedContactPoint{
		UID:      name, // Use name as UID for idempotency
		Name:     name, // Explicitly set name
		Type:     &cpType,
		Settings: r.buildSlackContactPointSettings(slackChannel),
	}

	params := &grafana_provisioning.PutContactpointParams{
		UID:  name,
		Body: contactPoint,
	}
	params.SetContext(ctx)

	_, err := r.provisioning.PutContactpoint(params)

	// Record metrics
	if err != nil {
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

	return err
}

func (r *grafanaReconciler) updateNotificationPolicy(ctx context.Context, teamSlug string, environments []*protoapi.TeamEnvironment) error {
	resp, err := r.provisioning.GetPolicyTree()
	if err != nil {
		return fmt.Errorf("getting policy tree: %w", err)
	}

	policyTree := resp.Payload
	if policyTree.Routes == nil {
		policyTree.Routes = []*models.Route{}
	}

	// Debug: Log existing routes before modification
	for i, route := range policyTree.Routes {
		if route.ObjectMatchers != nil {
			var matchers []string
			for _, matcher := range route.ObjectMatchers {
				if len(matcher) >= 3 {
					matchers = append(matchers, fmt.Sprintf("%s %s %s", matcher[0], matcher[1], matcher[2]))
				}
			}
			fmt.Printf("DEBUG: Existing route %d - Receiver: %s, Matchers: %v\n", i, route.Receiver, matchers)
		}
	}

	// Record policy tree size before modification
	r.metricPolicyTreeSize.Record(ctx, int64(len(policyTree.Routes)), metric.WithAttributes(
		attribute.String("operation", "read"),
		attribute.String("team", teamSlug),
	))

	// Remove existing routes for this team to ensure idempotent behavior
	filteredRoutes := r.filterRoutesForTeam(policyTree.Routes, teamSlug)

	newRoutes := r.buildNotificationRoutes(teamSlug, environments)
	filteredRoutes = append(filteredRoutes, newRoutes...)

	policyTree.Routes = filteredRoutes

	// Record policy tree size after modification
	r.metricPolicyTreeSize.Record(ctx, int64(len(policyTree.Routes)), metric.WithAttributes(
		attribute.String("operation", "write"),
		attribute.String("team", teamSlug),
	))

	params := &grafana_provisioning.PutPolicyTreeParams{
		Body: policyTree,
	}
	params.SetContext(ctx)

	_, err = r.provisioning.PutPolicyTree(params)

	// Record policy tree update metrics
	if err != nil {
		r.metricPolicyTreeUpdatesFailed.Add(ctx, 1, metric.WithAttributes(
			attribute.String("team", teamSlug),
		))
		return fmt.Errorf("updating policy tree: %w", err)
	} else {
		r.metricPolicyTreeUpdates.Add(ctx, 1, metric.WithAttributes(
			attribute.String("team", teamSlug),
		))
	}

	return nil
}

func (r *grafanaReconciler) filterRoutesForTeam(routes []*models.Route, teamSlug string) []*models.Route {
	var filteredRoutes []*models.Route
	for _, route := range routes {
		if !r.isRouteForTeam(route, teamSlug) {
			filteredRoutes = append(filteredRoutes, route)
		}
	}
	return filteredRoutes
}

func (r *grafanaReconciler) buildNotificationRoutes(teamSlug string, environments []*protoapi.TeamEnvironment) []*models.Route {
	var routes []*models.Route

	for _, env := range environments {
		if env.SlackAlertsChannel == "" {
			continue
		}

		contactPointName := r.buildContactPointName(teamSlug, env.EnvironmentName)

		teamMatcher := models.ObjectMatcher{"team", "=", teamSlug}
		envMatcher := models.ObjectMatcher{"environment", "=", env.EnvironmentName}

		route := &models.Route{
			Receiver:       contactPointName,
			ObjectMatchers: models.ObjectMatchers{teamMatcher, envMatcher},
			Continue:       false,
			GroupBy:        []string{"alertname", "team", "environment"},
			GroupWait:      defaultGroupWait,
			GroupInterval:  defaultGroupInterval,
			RepeatInterval: defaultRepeatInterval,
		}

		// Debug: Log what we're creating
		fmt.Printf("DEBUG: Creating route - Receiver: %s, Team: %s, Environment: %s\n",
			contactPointName, teamSlug, env.EnvironmentName)
		fmt.Printf("DEBUG: Route details - ObjectMatchers: %+v, GroupBy: %+v\n",
			route.ObjectMatchers, route.GroupBy)

		routes = append(routes, route)
	}

	return routes
}

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

func (r *grafanaReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	teamName := naisTeam.GetSlug()

	if r.provisioning != nil {
		if err := r.cleanupAlerting(ctx, teamName); err != nil {
			log.WithError(err).Warn("Failed to cleanup alerting configuration")
		}
	}

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

// Contact points follow the naming pattern: team-{teamSlug}-{envName}
func (r *grafanaReconciler) cleanupAlerting(ctx context.Context, teamSlug string) error {
	resp, err := r.provisioning.GetPolicyTree()
	if err != nil {
		return fmt.Errorf("getting policy tree: %w", err)
	}

	policyTree := resp.Payload
	if policyTree.Routes != nil {
		// Record policy tree size before cleanup
		r.metricPolicyTreeSize.Record(ctx, int64(len(policyTree.Routes)), metric.WithAttributes(
			attribute.String("operation", "cleanup_read"),
			attribute.String("team", teamSlug),
		))

		policyTree.Routes = r.filterRoutesForTeam(policyTree.Routes, teamSlug)

		// Record policy tree size after cleanup
		r.metricPolicyTreeSize.Record(ctx, int64(len(policyTree.Routes)), metric.WithAttributes(
			attribute.String("operation", "cleanup_write"),
			attribute.String("team", teamSlug),
		))

		params := &grafana_provisioning.PutPolicyTreeParams{
			Body: policyTree,
		}
		params.SetContext(ctx)

		_, err = r.provisioning.PutPolicyTree(params)
		if err != nil {
			r.metricPolicyTreeUpdatesFailed.Add(ctx, 1, metric.WithAttributes(
				attribute.String("team", teamSlug),
				attribute.String("operation", "cleanup"),
			))
			return fmt.Errorf("updating policy tree during cleanup: %w", err)
		} else {
			r.metricPolicyTreeUpdates.Add(ctx, 1, metric.WithAttributes(
				attribute.String("team", teamSlug),
				attribute.String("operation", "cleanup"),
			))
		}
	}

	return nil
}

func createSecurePassword() string {
	randomData := make([]byte, 32)
	_, err := rand.Read(randomData)
	if err != nil {
		panic("not enough entropy")
	}

	return base64.StdEncoding.EncodeToString(randomData)
}
