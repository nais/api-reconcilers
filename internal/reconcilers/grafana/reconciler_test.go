package grafana_reconciler_test

import (
	"context"
	"strconv"
	"testing"

	grafana_accesscontrol "github.com/grafana/grafana-openapi-client-go/client/access_control"
	grafana_serviceaccounts "github.com/grafana/grafana-openapi-client-go/client/service_accounts"
	grafana_teams "github.com/grafana/grafana-openapi-client-go/client/teams"
	"github.com/grafana/grafana-openapi-client-go/models"
	grafana_mock_access_control "github.com/nais/api-reconcilers/internal/mocks/grafana/access_control"
	grafana_mock_admin_users "github.com/nais/api-reconcilers/internal/mocks/grafana/admin_users"
	grafana_mock_service_accounts "github.com/nais/api-reconcilers/internal/mocks/grafana/service_accounts"
	grafana_mock_teams "github.com/nais/api-reconcilers/internal/mocks/grafana/teams"
	grafana_mock_users "github.com/nais/api-reconcilers/internal/mocks/grafana/users"
	grafana_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/grafana"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
)

func TestReconcile(t *testing.T) {
	ctx := context.Background()

	const (
		org                = "org"
		teamSlug           = "slug"
		teamPurpose        = "purpose"
		teamID             = 1
		teamIDAsString     = "1"
		authEndpoint       = "https://auth"
		resourceName       = "serviceaccounts"
		serviceAccoutEmail = "sa@example.com"
		serviceAccountID   = 1
	)

	teamName := teamSlug
	serviceAccountName := "team-" + teamSlug

	log, _ := test.NewNullLogger()

	t.Run("Create team", func(t *testing.T) {
		// Create team
		naisTeam := &protoapi.Team{
			Slug:    teamSlug,
			Purpose: teamPurpose,
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "grafana:create-team"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "grafana:create-service-account"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "grafana:assign-service-account-permissions"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{}, nil).
			Once()

		usersService := grafana_mock_users.NewMockClientService(t)
		teamsService := grafana_mock_teams.NewMockClientService(t)
		teamsService.EXPECT().
			SearchTeams(&grafana_teams.SearchTeamsParams{
				Query:   &teamName,
				Context: ctx,
			}).
			Return(&grafana_teams.SearchTeamsOK{
				Payload: &models.SearchTeamQueryResult{
					Teams: []*models.TeamDTO{},
				},
			}, nil).
			Once()
		teamsService.EXPECT().
			CreateTeamWithParams(&grafana_teams.CreateTeamParams{
				Body: &models.CreateTeamCommand{
					Name: teamName,
				},
				Context: ctx,
			}).
			Return(&grafana_teams.CreateTeamOK{
				Payload: &models.CreateTeamOKBody{
					TeamID: teamID,
				},
			}, nil).
			Once()
		teamsService.EXPECT().
			GetTeamMembersWithParams(&grafana_teams.GetTeamMembersParams{
				TeamID:  teamIDAsString,
				Context: ctx,
			}).
			Return(&grafana_teams.GetTeamMembersOK{
				Payload: []*models.TeamMemberDTO{},
			}, nil).
			Once()

		rbacService := grafana_mock_access_control.NewMockClientService(t)
		rbacService.EXPECT().
			GetResourcePermissionsWithParams(&grafana_accesscontrol.GetResourcePermissionsParams{
				Resource:   resourceName,
				ResourceID: strconv.Itoa(int(serviceAccountID)),
				Context:    ctx,
			}).
			Return(&grafana_accesscontrol.GetResourcePermissionsOK{
				Payload: []*models.ResourcePermissionDTO{},
			}, nil).
			Once()
		rbacService.EXPECT().
			SetResourcePermissions(&grafana_accesscontrol.SetResourcePermissionsParams{
				Body: &models.SetPermissionsCommand{
					Permissions: []*models.SetResourcePermissionCommand{
						{
							Permission: "Edit",
							TeamID:     teamID,
						},
					},
				},
				Resource:   resourceName,
				ResourceID: strconv.Itoa(int(serviceAccountID)),
				Context:    ctx,
			}).
			Return(&grafana_accesscontrol.SetResourcePermissionsOK{}, nil).
			Once()

		serviceAccountsService := grafana_mock_service_accounts.NewMockClientService(t)
		serviceAccountsService.EXPECT().
			SearchOrgServiceAccountsWithPaging(&grafana_serviceaccounts.SearchOrgServiceAccountsWithPagingParams{
				Query:   &serviceAccountName,
				Context: ctx,
			}).
			Return(&grafana_serviceaccounts.SearchOrgServiceAccountsWithPagingOK{
				Payload: &models.SearchOrgServiceAccountsResult{},
			}, nil).
			Once()
		serviceAccountsService.EXPECT().
			CreateServiceAccount(&grafana_serviceaccounts.CreateServiceAccountParams{
				Body: &models.CreateServiceAccountForm{
					Name: serviceAccountName,
				},
				Context: ctx,
			}).
			Return(&grafana_serviceaccounts.CreateServiceAccountCreated{
				Payload: &models.ServiceAccountDTO{
					ID: serviceAccountID,
				},
			}, nil).
			Once()

		adminUsersService := grafana_mock_admin_users.NewMockClientService(t)

		reconciler, err := grafana_reconciler.New(usersService, teamsService, rbacService, serviceAccountsService, adminUsersService)
		if err != nil {
			t.Fatal(err)
		}

		err = reconciler.Reconcile(ctx, apiClient, naisTeam, log)
		if err != nil {
			t.Fatal(err)
		}
	})
}
