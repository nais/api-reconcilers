package grafana_reconciler_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	grafana_accesscontrol "github.com/grafana/grafana-openapi-client-go/client/access_control"
	grafana_admin_users "github.com/grafana/grafana-openapi-client-go/client/admin_users"
	grafana_serviceaccounts "github.com/grafana/grafana-openapi-client-go/client/service_accounts"
	grafana_teams "github.com/grafana/grafana-openapi-client-go/client/teams"
	grafana_users "github.com/grafana/grafana-openapi-client-go/client/users"
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

	members := []*protoapi.TeamMember{
		{
			User: &protoapi.User{
				Email: "user1@nav.no",
				Name:  "User 1",
			},
		},
		{
			User: &protoapi.User{
				Email: "user2@nav.no",
				Name:  "User 2",
			},
		},
	}

	naisTeam := &protoapi.Team{
		Slug:    teamSlug,
		Purpose: teamPurpose,
	}

	teamName := teamSlug
	serviceAccountName := "team-" + teamSlug

	log, _ := test.NewNullLogger()

	t.Run("No data, create the first team", func(t *testing.T) {
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
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "grafana:add-team-member"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Twice()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "grafana:create-user"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Twice()

		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{
				Nodes: members,
			}, nil).
			Once()

		usersService := grafana_mock_users.NewMockClientService(t)
		usersService.EXPECT().
			GetUserByLoginOrEmailWithParams(&grafana_users.GetUserByLoginOrEmailParams{
				LoginOrEmail: members[0].User.Email,
				Context:      ctx,
			}).
			Return(&grafana_users.GetUserByLoginOrEmailOK{}, fmt.Errorf("no user found")).
			Once()

		usersService.EXPECT().
			GetUserByLoginOrEmailWithParams(&grafana_users.GetUserByLoginOrEmailParams{
				LoginOrEmail: members[1].User.Email,
				Context:      ctx,
			}).
			Return(&grafana_users.GetUserByLoginOrEmailOK{}, fmt.Errorf("no user found")).
			Once()

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
			AddTeamMemberWithParams(&grafana_teams.AddTeamMemberParams{
				Body: &models.AddTeamMemberCommand{
					UserID: 1,
				},
				TeamID:  teamIDAsString,
				Context: ctx,
			}).
			Return(&grafana_teams.AddTeamMemberOK{}, nil).
			Once()
		teamsService.EXPECT().
			AddTeamMemberWithParams(&grafana_teams.AddTeamMemberParams{
				Body: &models.AddTeamMemberCommand{
					UserID: 2,
				},
				TeamID:  teamIDAsString,
				Context: ctx,
			}).
			Return(&grafana_teams.AddTeamMemberOK{}, nil).
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
		adminUsersService.
			On("AdminCreateUserWithParams", mock.MatchedBy(func(params *grafana_admin_users.AdminCreateUserParams) bool {
				return params.Body.Email == members[0].User.Email
			})).
			Return(&grafana_admin_users.AdminCreateUserOK{
				Payload: &models.AdminCreateUserResponse{
					ID: 1,
				},
			}, nil).
			Once()
		adminUsersService.
			On("AdminCreateUserWithParams", mock.MatchedBy(func(params *grafana_admin_users.AdminCreateUserParams) bool {
				return params.Body.Email == members[1].User.Email
			})).
			Return(&grafana_admin_users.AdminCreateUserOK{
				Payload: &models.AdminCreateUserResponse{
					ID: 2,
				},
			}, nil).
			Once()

		reconciler, err := grafana_reconciler.New(usersService, teamsService, rbacService, serviceAccountsService, adminUsersService)
		if err != nil {
			t.Fatal(err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Delete team member", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:    teamSlug,
			Purpose: teamPurpose,
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "grafana:remove-team-member"
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
			Return(&protoapi.ListTeamMembersResponse{
				Nodes: members[0:1],
			}, nil).
			Once()

		usersService := grafana_mock_users.NewMockClientService(t)
		usersService.EXPECT().
			GetUserByLoginOrEmailWithParams(&grafana_users.GetUserByLoginOrEmailParams{
				LoginOrEmail: members[0].User.Email,
				Context:      ctx,
			}).
			Return(&grafana_users.GetUserByLoginOrEmailOK{
				Payload: &models.UserProfileDTO{
					ID: 1,
				},
			}, nil).
			Once()

		teamsService := grafana_mock_teams.NewMockClientService(t)
		teamsService.EXPECT().
			RemoveTeamMemberWithParams(&grafana_teams.RemoveTeamMemberParams{
				UserID:  2,
				TeamID:  teamIDAsString,
				Context: ctx,
			}).
			Return(&grafana_teams.RemoveTeamMemberOK{}, nil).
			Once()
		teamsService.EXPECT().
			SearchTeams(&grafana_teams.SearchTeamsParams{
				Query:   &teamName,
				Context: ctx,
			}).
			Return(&grafana_teams.SearchTeamsOK{
				Payload: &models.SearchTeamQueryResult{
					Teams: []*models.TeamDTO{
						{
							ID:   teamID,
							Name: teamName,
						},
					},
				},
			}, nil).
			Once()
		teamsService.EXPECT().
			GetTeamMembersWithParams(&grafana_teams.GetTeamMembersParams{
				TeamID:  teamIDAsString,
				Context: ctx,
			}).
			Return(&grafana_teams.GetTeamMembersOK{
				Payload: []*models.TeamMemberDTO{
					{
						UserID: 1,
						Email:  members[0].User.Email,
					},
					{
						UserID: 2,
						Email:  members[1].User.Email,
					},
				},
			}, nil).
			Once()

		rbacService := grafana_mock_access_control.NewMockClientService(t)
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

		serviceAccounts := make([]*models.ServiceAccountDTO, 0)
		serviceAccounts = append(serviceAccounts, &models.ServiceAccountDTO{
			ID:   serviceAccountID,
			Name: serviceAccountName,
		})
		serviceAccountsService.EXPECT().
			SearchOrgServiceAccountsWithPaging(&grafana_serviceaccounts.SearchOrgServiceAccountsWithPagingParams{
				Query:   &serviceAccountName,
				Context: ctx,
			}).
			Return(&grafana_serviceaccounts.SearchOrgServiceAccountsWithPagingOK{
				Payload: &models.SearchOrgServiceAccountsResult{
					ServiceAccounts: serviceAccounts,
				},
			}, nil).
			Once()

		adminUsersService := grafana_mock_admin_users.NewMockClientService(t)

		reconciler, err := grafana_reconciler.New(usersService, teamsService, rbacService, serviceAccountsService, adminUsersService)
		if err != nil {
			t.Fatal(err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Test service account resource permissions", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:    teamSlug,
			Purpose: teamPurpose,
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "grafana:assign-service-account-permissions"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{
				Nodes: members,
			}, nil).
			Once()

		usersService := grafana_mock_users.NewMockClientService(t)
		usersService.EXPECT().
			GetUserByLoginOrEmailWithParams(&grafana_users.GetUserByLoginOrEmailParams{
				LoginOrEmail: members[0].User.Email,
				Context:      ctx,
			}).
			Return(&grafana_users.GetUserByLoginOrEmailOK{
				Payload: &models.UserProfileDTO{
					ID: 1,
				},
			}, nil).
			Once()
		usersService.EXPECT().
			GetUserByLoginOrEmailWithParams(&grafana_users.GetUserByLoginOrEmailParams{
				LoginOrEmail: members[1].User.Email,
				Context:      ctx,
			}).
			Return(&grafana_users.GetUserByLoginOrEmailOK{
				Payload: &models.UserProfileDTO{
					ID: 2,
				},
			}, nil).
			Once()

		teamsService := grafana_mock_teams.NewMockClientService(t)
		teamsService.EXPECT().
			SearchTeams(&grafana_teams.SearchTeamsParams{
				Query:   &teamName,
				Context: ctx,
			}).
			Return(&grafana_teams.SearchTeamsOK{
				Payload: &models.SearchTeamQueryResult{
					Teams: []*models.TeamDTO{
						{
							ID:   teamID,
							Name: teamName,
						},
					},
				},
			}, nil).
			Once()
		teamsService.EXPECT().
			GetTeamMembersWithParams(&grafana_teams.GetTeamMembersParams{
				TeamID:  teamIDAsString,
				Context: ctx,
			}).
			Return(&grafana_teams.GetTeamMembersOK{
				Payload: []*models.TeamMemberDTO{
					{
						UserID: 1,
						Email:  members[0].User.Email,
					},
					{
						UserID: 2,
						Email:  members[1].User.Email,
					},
				},
			}, nil).
			Once()

		rbacService := grafana_mock_access_control.NewMockClientService(t)
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

		serviceAccounts := make([]*models.ServiceAccountDTO, 0)
		serviceAccounts = append(serviceAccounts, &models.ServiceAccountDTO{
			ID:   serviceAccountID,
			Name: serviceAccountName,
		})
		serviceAccountsService.EXPECT().
			SearchOrgServiceAccountsWithPaging(&grafana_serviceaccounts.SearchOrgServiceAccountsWithPagingParams{
				Query:   &serviceAccountName,
				Context: ctx,
			}).
			Return(&grafana_serviceaccounts.SearchOrgServiceAccountsWithPagingOK{
				Payload: &models.SearchOrgServiceAccountsResult{
					ServiceAccounts: serviceAccounts,
				},
			}, nil).
			Once()

		adminUsersService := grafana_mock_admin_users.NewMockClientService(t)

		reconciler, err := grafana_reconciler.New(usersService, teamsService, rbacService, serviceAccountsService, adminUsersService)
		if err != nil {
			t.Fatal(err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Delete team", func(t *testing.T) {
		apiClient, mockServer := apiclient.NewMockClient(t)
		auditLogsService := mockServer.AuditLogs
		auditLogsService.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "grafana:removed-team"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		teamsService := grafana_mock_teams.NewMockClientService(t)
		teamsService.EXPECT().
			SearchTeams(&grafana_teams.SearchTeamsParams{
				Query:   &teamName,
				Context: ctx,
			}).
			Return(&grafana_teams.SearchTeamsOK{
				Payload: &models.SearchTeamQueryResult{
					Teams: []*models.TeamDTO{
						{
							ID:   teamID,
							Name: teamName,
						},
					},
				},
			}, nil).
			Once()
		teamsService.EXPECT().
			DeleteTeamByID(teamIDAsString).
			Return(&grafana_teams.DeleteTeamByIDOK{}, nil).
			Once()

		reconciler, err := grafana_reconciler.New(nil, teamsService, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}

		if err := reconciler.Delete(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatal(err)
		}
	})
}
