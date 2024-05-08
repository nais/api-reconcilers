package grafana_reconciler

import (
	"context"
	"strconv"

	"golang.org/x/exp/maps"

	"github.com/nais/api-reconcilers/internal/reconcilers"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
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
) (*grafanaReconciler, error) {
	return &grafanaReconciler{
		users:           users,
		teams:           teams,
		rbac:            rbac,
		serviceAccounts: serviceAccounts,
		adminUsers:      adminUsers,
	}, nil
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

func (r *grafanaReconciler) getOrCreateTeamID(teamName string) (int64, error) {
	params := &grafana_teams.SearchTeamsParams{
		Query: &teamName,
	}

	searchResp, err := r.teams.SearchTeams(params)
	if err != nil {
		return 0, err
	}

	// TODO: Handle paging?
	for _, team := range searchResp.Payload.Teams {
		if team.Name == teamName {
			return team.ID, nil
		}
	}

	createResp, err := r.teams.CreateTeam(&models.CreateTeamCommand{
		Name: teamName,
	})
	if err != nil {
		return 0, err
	}

	return createResp.Payload.TeamID, nil
}

func (r *grafanaReconciler) getOrCreateUser(user *protoapi.User) (int64, error) {
	existingUser, err := r.users.GetUserByLoginOrEmail(user.GetEmail())
	if err == nil {
		return existingUser.GetPayload().ID, nil
	}

	newUser, err := r.adminUsers.AdminCreateUser(&models.AdminCreateUserForm{
		Email:    user.GetEmail(),
		Login:    user.GetEmail(),
		Name:     user.GetName(),
		Password: models.Password(create_secure_password()),
	})

	if err != nil {
		return 0, err
	}

	return newUser.GetPayload().ID, nil
}

func (r *grafanaReconciler) syncTeamMembers(teamID int64, naisTeamMembers []*protoapi.TeamMember, grafanaUserIDMap map[string]int64) error {
	teamIDString := strconv.Itoa(int(teamID))
	grafanaExistingMembers, err := r.teams.GetTeamMembers(teamIDString)
	if err != nil {
		return err
	}

	existingMembers := make(map[string]int64)
	for _, member := range grafanaExistingMembers.GetPayload() {
		existingMembers[member.Email] = member.UserID
	}

	membersToRemove := make([]int64, 0)
	for email, userID := range existingMembers {
		if !grafanaMemberExistsInTeamMembers(naisTeamMembers, email) {
			membersToRemove = append(membersToRemove, userID)
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

	for _, userID := range membersToRemove {
		_, err = r.teams.RemoveTeamMember(userID, teamIDString)
		if err != nil {
			return err
		}
	}

	for _, email := range membersToAdd {
		_, err = r.teams.AddTeamMember(teamIDString, &models.AddTeamMemberCommand{
			UserID: grafanaUserIDMap[email],
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func grafanaMemberExistsInTeamMembers(naisTeamMembers []*protoapi.TeamMember, email string) bool {
	for _, user := range naisTeamMembers {
		if email == user.GetUser().Email {
			return true
		}
	}
	return false
}

func teamMemberExistsInGrafanaMembers(grafanaTeamMemberEmails []string, email string) bool {
	for _, grafanaEmail := range grafanaTeamMemberEmails {
		if email == grafanaEmail {
			return true
		}
	}
	return false
}

func (r *grafanaReconciler) getOrCreateServiceAccount(teamName string) (int64, error) {
	params := &grafana_serviceaccounts.SearchOrgServiceAccountsWithPagingParams{
		Query: &teamName,
	}
	searchResp, err := r.serviceAccounts.SearchOrgServiceAccountsWithPaging(params)
	if err != nil {
		return 0, err
	}

	// TODO: Handle paging?
	for _, serviceAccount := range searchResp.Payload.ServiceAccounts {
		if serviceAccount.Name == teamName {
			return serviceAccount.ID, nil
		}
	}

	createParams := &grafana_serviceaccounts.CreateServiceAccountParams{
		Body: &models.CreateServiceAccountForm{
			Name: teamName,
			//Role: "Edit",
		},
	}

	serviceAccountOk, err := r.serviceAccounts.CreateServiceAccount(createParams)
	if err != nil {
		return 0, err
	}

	return serviceAccountOk.GetPayload().ID, err
}

func (r *grafanaReconciler) setServiceAccountMembers(teamID int64, serviceAccountID int64) error {
	_, err := r.rbac.SetResourcePermissions(&grafana_accesscontrol.SetResourcePermissionsParams{
		Body: &models.SetPermissionsCommand{
			Permissions: []*models.SetResourcePermissionCommand{
				{
					Permission: "Edit",
					TeamID:     teamID,
				},
			},
		},
		Resource:   "serviceaccounts",
		ResourceID: strconv.Itoa(int(serviceAccountID)),
	})
	return err
}

// FIXME
func create_secure_password() string {
	return "password"
}

func (r *grafanaReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {

	// Check if team exists in Grafana, otherwise create it. Keep the ID.
	teamID, err := r.getOrCreateTeamID(naisTeam.GetSlug())
	if err != nil {
		return err
	}

	// Check if all users exist in Grafana, otherwise create them and set a random password. Keep the user IDs.
	naisTeamMembers, err := reconcilers.GetTeamMembers(ctx, client.Teams(), naisTeam.Slug)
	if err != nil {
		return err
	}

	userIDs := make(map[string]int64)
	for _, member := range naisTeamMembers {
		user := member.GetUser()
		userID, err := r.getOrCreateUser(user)
		if err != nil {
			return err
		}
		userIDs[user.Email] = userID
	}

	// Make sure memberships are exactly equal in Grafana and local dataset.
	// Remove users that don't exist. Make sure the permission is set to "Editor".
	// This also means to remove the Grafana "admin" user from team memberships.
	// The admin user can be assumed to hold the id `1`.
	err = r.syncTeamMembers(teamID, naisTeamMembers, userIDs)
	if err != nil {
		return err
	}

	// Check if the service account exists in Grafana, otherwise create it.
	// The service account name should be "team-<team>".
	serviceAccountId, err := r.getOrCreateServiceAccount("team-" + naisTeam.GetSlug())
	if err != nil {
		return err
	}

	// Add the team to the service account with "Edit" permissions.
	// Make sure the team is the only team or user connected with the service account.
	// This means also to remove the Grafana "admin" user from service account membership.
	return r.setServiceAccountMembers(teamID, serviceAccountId)
}

func (r *grafanaReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	return nil
}
