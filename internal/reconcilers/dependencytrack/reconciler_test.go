package dependencytrack_reconciler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	dependencytrack_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/dependencytrack"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/nais/dependencytrack/pkg/client"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		grpcServers.Reconcilers.EXPECT().
			State(mock.Anything, &protoapi.GetReconcilerStateRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug}).
			Return(nil, status.Error(codes.NotFound, "state not found")).
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
		grpcServers.Reconcilers.EXPECT().
			SaveState(mock.Anything, mock.MatchedBy(func(req *protoapi.SaveReconcilerStateRequest) bool {
				st := dependencytrack_reconciler.DependencyTrackState{}
				_ = json.Unmarshal(req.Value, &st)

				return req.ReconcilerName == "nais:dependencytrack" &&
					req.TeamSlug == teamSlug &&
					st.TeamID == teamID &&
					len(st.Members) == 1 &&
					st.Members[0] == user
			})).
			Return(&protoapi.SaveReconcilerStateResponse{}, nil).
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
		grpcServers.Reconcilers.EXPECT().
			State(mock.Anything, &protoapi.GetReconcilerStateRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug}).
			Return(&protoapi.GetReconcilerStateResponse{
				State: &protoapi.ReconcilerState{
					Value: []byte(fmt.Sprintf(`{"teamId": %q}`, teamID)),
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
		grpcServers.Reconcilers.EXPECT().
			SaveState(mock.Anything, mock.MatchedBy(func(req *protoapi.SaveReconcilerStateRequest) bool {
				st := dependencytrack_reconciler.DependencyTrackState{}
				_ = json.Unmarshal(req.Value, &st)

				return req.ReconcilerName == "nais:dependencytrack" &&
					req.TeamSlug == teamSlug &&
					st.TeamID == teamID &&
					len(st.Members) == 1 &&
					st.Members[0] == user
			})).
			Return(&protoapi.SaveReconcilerStateResponse{}, nil).
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
		grpcServers.Reconcilers.EXPECT().
			State(mock.Anything, &protoapi.GetReconcilerStateRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug}).
			Return(&protoapi.GetReconcilerStateResponse{
				State: &protoapi.ReconcilerState{
					Value: []byte(fmt.Sprintf(`{"teamId": %q, "members": [%q]}`, teamID, user)),
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
		grpcServers.Reconcilers.EXPECT().
			SaveState(mock.Anything, mock.MatchedBy(func(req *protoapi.SaveReconcilerStateRequest) bool {
				st := dependencytrack_reconciler.DependencyTrackState{}
				_ = json.Unmarshal(req.Value, &st)

				return req.ReconcilerName == "nais:dependencytrack" &&
					req.TeamSlug == teamSlug &&
					st.TeamID == teamID &&
					len(st.Members) == 1 &&
					st.Members[0] == user
			})).
			Return(&protoapi.SaveReconcilerStateResponse{}, nil).
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
		grpcServers.Reconcilers.EXPECT().
			State(mock.Anything, &protoapi.GetReconcilerStateRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug}).
			Return(&protoapi.GetReconcilerStateResponse{
				State: &protoapi.ReconcilerState{
					Value: []byte(fmt.Sprintf(`{"teamId": %q, "members": [%q]}`, teamID, unknownMember)),
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
		grpcServers.Reconcilers.EXPECT().
			SaveState(mock.Anything, mock.MatchedBy(func(req *protoapi.SaveReconcilerStateRequest) bool {
				st := dependencytrack_reconciler.DependencyTrackState{}
				_ = json.Unmarshal(req.Value, &st)

				return req.ReconcilerName == "nais:dependencytrack" &&
					req.TeamSlug == teamSlug &&
					st.TeamID == teamID &&
					len(st.Members) == 1 &&
					st.Members[0] == user
			})).
			Return(&protoapi.SaveReconcilerStateResponse{}, nil).
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
	naisTeam := &protoapi.Team{
		Slug:    teamSlug,
		Purpose: "some purpose",
	}
	log, _ := test.NewNullLogger()

	t.Run("team exists, delete team from api should remove team from dependencytrack", func(t *testing.T) {
		dpClient := dependencytrack_reconciler.NewMockClient(t)
		dpClient.EXPECT().DeleteTeam(mock.Anything, teamID).Return(nil).Once()

		apiClient, grpcServers := apiclient.NewMockClient(t)
		grpcServers.Reconcilers.EXPECT().
			State(mock.Anything, &protoapi.GetReconcilerStateRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug}).
			Return(&protoapi.GetReconcilerStateResponse{
				State: &protoapi.ReconcilerState{
					Value: []byte(fmt.Sprintf(`{"teamId": %q}`, teamID)),
				},
			}, nil).
			Once()
		grpcServers.Reconcilers.EXPECT().
			DeleteState(mock.Anything, &protoapi.DeleteReconcilerStateRequest{ReconcilerName: "nais:dependencytrack", TeamSlug: teamSlug}).
			Return(&protoapi.DeleteReconcilerStateResponse{}, nil).
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
