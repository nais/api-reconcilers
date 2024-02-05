package dependencytrack_reconciler_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	dependencytrack_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/dependencytrack"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/nais/dependencytrack/pkg/client"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
)

func TestMissingConfig(t *testing.T) {
	reconciler, err := dependencytrack_reconciler.New("some-endpoint", "username", "")
	if reconciler != nil {
		t.Errorf("expected reconciler to be nil")
	}

	if err == nil {
		t.Errorf("expected error")
	}
}

func TestDependencytrackReconciler_Reconcile(t *testing.T) {
	ctx := context.Background()
	teamSlug := "someTeam"
	teamPurpose := "someDescription"
	user := "user@example.com"
	teamID := uuid.New().String()
	log, _ := test.NewNullLogger()
	naisTeam := &protoapi.Team{
		Slug:    teamSlug,
		Purpose: teamPurpose,
	}

	t.Run("team does not exist, new team created and new members added", func(t *testing.T) {
		dpClient := dependencytrack_reconciler.NewMockClient(t)
		dpClient.EXPECT().
			CreateTeam(mock.Anything, teamSlug, []client.Permission{
				client.ViewPortfolioPermission,
				client.ViewVulnerabilityPermission,
				client.ViewPolicyViolationPermission,
			}).
			Return(&client.Team{
				Uuid:      teamID,
				Name:      teamSlug,
				OidcUsers: nil,
			}, nil).
			Once()
		dpClient.EXPECT().
			CreateOidcUser(ctx, user).
			Return(nil).
			Once()
		dpClient.EXPECT().
			AddToTeam(ctx, user, teamID).
			Return(nil).
			Once()

		apiClient, grpcServers := apiclient.NewMockClient(t)
		grpcServers.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{}, nil).
			Once()
		grpcServers.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{Nodes: []*protoapi.TeamMember{
				{
					User: &protoapi.User{
						Email: user,
					},
				},
			}}, nil).
			Once()
		grpcServers.ReconcilerResources.EXPECT().
			Save(mock.Anything, &protoapi.SaveReconcilerResourceRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug, Resources: []*protoapi.NewReconcilerResource{
				{
					Name:  "team_id",
					Value: teamID,
				},
				{
					Name:  "members",
					Value: user,
				},
			}}).
			Return(&protoapi.SaveReconcilerResourceResponse{}, nil).
			Once()
		grpcServers.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "dependencytrack:team:create"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		grpcServers.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "dependencytrack:team:add-member"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		reconciler, err := dependencytrack_reconciler.New("", "", "", dependencytrack_reconciler.WithDependencyTrackClient(dpClient))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		err = reconciler.Reconcile(ctx, apiClient, naisTeam, log)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("team exists, new members added", func(t *testing.T) {
		dpClient := dependencytrack_reconciler.NewMockClient(t)
		dpClient.EXPECT().
			CreateOidcUser(ctx, user).
			Return(nil).
			Once()
		dpClient.EXPECT().
			AddToTeam(ctx, user, teamID).
			Return(nil).
			Once()

		apiClient, grpcServers := apiclient.NewMockClient(t)
		grpcServers.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{
				Nodes: []*protoapi.ReconcilerResource{
					{
						Name:  "team_id",
						Value: teamID,
					},
				},
			}, nil).
			Once()
		grpcServers.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{Nodes: []*protoapi.TeamMember{
				{
					User: &protoapi.User{
						Email: user,
					},
				},
			}}, nil).
			Once()
		grpcServers.ReconcilerResources.EXPECT().
			Save(mock.Anything, &protoapi.SaveReconcilerResourceRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug, Resources: []*protoapi.NewReconcilerResource{
				{
					Name:  "team_id",
					Value: teamID,
				},
				{
					Name:  "members",
					Value: user,
				},
			}}).
			Return(&protoapi.SaveReconcilerResourceResponse{}, nil).
			Once()
		grpcServers.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "dependencytrack:team:add-member"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		reconciler, err := dependencytrack_reconciler.New("", "", "", dependencytrack_reconciler.WithDependencyTrackClient(dpClient))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		err = reconciler.Reconcile(ctx, apiClient, naisTeam, log)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("team exists all input members exists, no new members added", func(t *testing.T) {
		dpClient := dependencytrack_reconciler.NewMockClient(t)

		apiClient, grpcServers := apiclient.NewMockClient(t)
		grpcServers.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{
				Nodes: []*protoapi.ReconcilerResource{
					{
						Name:  "team_id",
						Value: teamID,
					},
					{
						Name:  "members",
						Value: user,
					},
				},
			}, nil).
			Once()
		grpcServers.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{Nodes: []*protoapi.TeamMember{
				{
					User: &protoapi.User{
						Email: user,
					},
				},
			}}, nil).
			Once()
		grpcServers.ReconcilerResources.EXPECT().
			Save(mock.Anything, &protoapi.SaveReconcilerResourceRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug, Resources: []*protoapi.NewReconcilerResource{
				{
					Name:  "team_id",
					Value: teamID,
				},
				{
					Name:  "members",
					Value: user,
				},
			}}).
			Return(&protoapi.SaveReconcilerResourceResponse{}, nil).
			Once()

		reconciler, err := dependencytrack_reconciler.New("", "", "", dependencytrack_reconciler.WithDependencyTrackClient(dpClient))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		err = reconciler.Reconcile(ctx, apiClient, naisTeam, log)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("usermembership removed from existing team", func(t *testing.T) {
		unknownMember := "unknown@example.com"

		dpClient := dependencytrack_reconciler.NewMockClient(t)
		dpClient.EXPECT().
			CreateOidcUser(ctx, user).
			Return(nil).
			Once()
		dpClient.EXPECT().
			AddToTeam(ctx, user, teamID).
			Return(nil).
			Once()
		dpClient.EXPECT().
			DeleteUserMembership(ctx, teamID, unknownMember).
			Return(nil).
			Once()

		apiClient, grpcServers := apiclient.NewMockClient(t)
		grpcServers.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{
				Nodes: []*protoapi.ReconcilerResource{
					{
						Name:  "team_id",
						Value: teamID,
					},
					{
						Name:  "members",
						Value: unknownMember,
					},
				},
			}, nil).
			Once()
		grpcServers.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{Nodes: []*protoapi.TeamMember{
				{
					User: &protoapi.User{
						Email: user,
					},
				},
			}}, nil).
			Once()
		grpcServers.ReconcilerResources.EXPECT().
			Save(mock.Anything, &protoapi.SaveReconcilerResourceRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug, Resources: []*protoapi.NewReconcilerResource{
				{
					Name:  "team_id",
					Value: teamID,
				},
				{
					Name:  "members",
					Value: user,
				},
			}}).
			Return(&protoapi.SaveReconcilerResourceResponse{}, nil).
			Once()
		grpcServers.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "dependencytrack:team:add-member"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		grpcServers.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "dependencytrack:team:delete-member"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		reconciler, err := dependencytrack_reconciler.New("", "", "", dependencytrack_reconciler.WithDependencyTrackClient(dpClient))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		err = reconciler.Reconcile(ctx, apiClient, naisTeam, log)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})
}

func TestDependencytrackReconciler_Delete(t *testing.T) {
	ctx := context.Background()
	teamID := uuid.New().String()
	teamSlug := "some-team"
	user := "user@example.com"
	naisTeam := &protoapi.Team{
		Slug:    teamSlug,
		Purpose: "some purpose",
	}
	log, _ := test.NewNullLogger()

	t.Run("team exists, delete team from teams-backend should remove team from dependencytrack", func(t *testing.T) {
		dpClient := dependencytrack_reconciler.NewMockClient(t)
		dpClient.EXPECT().DeleteTeam(mock.Anything, teamID).Return(nil).Once()

		apiClient, grpcServers := apiclient.NewMockClient(t)
		grpcServers.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{
				Nodes: []*protoapi.ReconcilerResource{
					{
						Name:  "team_id",
						Value: teamID,
					},
				},
			}, nil).
			Once()
		grpcServers.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{Nodes: []*protoapi.TeamMember{
				{
					User: &protoapi.User{
						Email: user,
					},
				},
			}}, nil).
			Once()
		grpcServers.ReconcilerResources.EXPECT().
			Delete(mock.Anything, &protoapi.DeleteReconcilerResourcesRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug}).
			Return(&protoapi.DeleteReconcilerResourcesResponse{}, nil).
			Once()

		reconciler, err := dependencytrack_reconciler.New("", "", "", dependencytrack_reconciler.WithDependencyTrackClient(dpClient))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		err = reconciler.Delete(ctx, apiClient, naisTeam, log)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})
}
