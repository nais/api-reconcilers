package grafana_reconciler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/nais/api-reconcilers/internal/reconcilers"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"

	grafana_accesscontrol "github.com/grafana/grafana-openapi-client-go/client/access_control"
	grafana_admin_users "github.com/grafana/grafana-openapi-client-go/client/admin_users"
	grafana_serviceaccounts "github.com/grafana/grafana-openapi-client-go/client/service_accounts"
	grafana_teams "github.com/grafana/grafana-openapi-client-go/client/teams"
	grafana_users "github.com/grafana/grafana-openapi-client-go/client/users"
	"github.com/grafana/grafana-openapi-client-go/models"
)

const (
	grafanaReconcilerName = "grafana"
)

type grafanaReconciler struct {
	users           grafana_users.ClientService
	teams           grafana_teams.ClientService
	rbac            grafana_accesscontrol.ClientService
	serviceAccounts grafana_serviceaccounts.ClientService
	adminUsers      grafana_admin_users.ClientService
}

func New(
	users grafana_users.ClientService,
	teams grafana_teams.ClientService,
	rbac grafana_accesscontrol.ClientService,
	serviceAccounts grafana_serviceaccounts.ClientService,
	adminUsers grafana_admin_users.ClientService,
) reconcilers.Reconciler {
	return &grafanaReconciler{
		users:           users,
		teams:           teams,
		rbac:            rbac,
		serviceAccounts: serviceAccounts,
		adminUsers:      adminUsers,
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

	membersToRemove := make(map[int64]string, 0)
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
	// Check if team exists in Grafana, otherwise create it. Keep the ID.
	teamID, err := r.getOrCreateTeam(ctx, naisTeam.GetSlug())
	if err != nil {
		return err
	}

	// Check if all users exist in Grafana, otherwise create them and set a random password. Keep the user IDs.
	naisTeamMembers, err := reconcilers.GetTeamMembers(ctx, client.Teams(), naisTeam.Slug)
	if err != nil {
		return err
	}

	// Make a map of email addresses to user ids.
	userIDs := make(map[string]int64)
	for _, member := range naisTeamMembers {
		user := member.GetUser()
		userID, err := r.getOrCreateUser(ctx, user)
		if err != nil {
			return err
		}
		userIDs[user.Email] = userID
	}

	// Make sure memberships are exactly equal in Grafana and local dataset.
	// Remove users that don't exist. Make sure the permission is set to "Editor".
	// This also means to remove the Grafana "admin" user from team memberships.
	// The admin user can be assumed to hold the id `1`.
	err = r.syncTeamMembers(ctx, teamID, naisTeamMembers, userIDs)
	if err != nil {
		return err
	}

	// Check if the service account exists in Grafana, otherwise create it.
	// The service account name should be "team-<team>".
	serviceAccountId, err := r.getOrCreateServiceAccount(ctx, "team-"+naisTeam.GetSlug())
	if err != nil {
		return err
	}

	// Add the team to the service account with "Edit" permissions.
	// Make sure the team is the only team or user connected with the service account.
	// This means also to remove the Grafana "admin" user from service account membership.
	return r.setServiceAccountMembers(ctx, teamID, serviceAccountId)
}

// We trust Grafana to clean up any dangling references to our deleted team.
func (r *grafanaReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	teamName := naisTeam.GetSlug()
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

// Generate a random password with 256 bits of entropy.
func createSecurePassword() string {
	randomData := make([]byte, 32)
	_, err := rand.Read(randomData)
	if err != nil {
		panic("not enough entropy")
	}

	return base64.StdEncoding.EncodeToString(randomData)
}
