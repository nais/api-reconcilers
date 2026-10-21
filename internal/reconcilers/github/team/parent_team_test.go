package github_team_reconciler

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-github/v50/github"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGetOrCreateParentTeam(t *testing.T) {
	ctx := t.Context()
	parent := &github.Team{ID: new(int64(123)), Slug: new(parentTeamSlug)}
	response := func(code int) *github.Response {
		return &github.Response{Response: &http.Response{StatusCode: code}}
	}

	t.Run("reuse existing parent", func(t *testing.T) {
		teams := NewMockTeamsService(t)
		teams.EXPECT().GetTeamBySlug(ctx, "org", parentTeamSlug).
			Return(parent, response(http.StatusOK), nil).Once()
		r := &githubTeamReconciler{org: "org", teamsService: teams}
		team, err := r.getOrCreateParentTeam(ctx)
		require.NoError(t, err)
		require.Same(t, parent, team)
	})

	t.Run("create missing parent", func(t *testing.T) {
		teams := NewMockTeamsService(t)
		teams.EXPECT().GetTeamBySlug(ctx, "org", parentTeamSlug).
			Return(nil, response(http.StatusNotFound), errors.New("not found")).Once()
		teams.EXPECT().CreateTeam(ctx, "org", github.NewTeam{Name: parentTeamSlug, Description: new("Parent team for all teams synced by Nais."), Privacy: new("closed")}).
			Return(parent, response(http.StatusCreated), nil).Once()
		r := &githubTeamReconciler{org: "org", teamsService: teams}
		team, err := r.getOrCreateParentTeam(ctx)
		require.NoError(t, err)
		require.Same(t, parent, team)
	})

	t.Run("concurrent creation", func(t *testing.T) {
		teams := NewMockTeamsService(t)
		teams.EXPECT().GetTeamBySlug(ctx, "org", parentTeamSlug).
			Return(nil, response(http.StatusNotFound), errors.New("not found")).Once()
		teams.EXPECT().CreateTeam(ctx, "org", github.NewTeam{Name: parentTeamSlug, Description: new("Parent team for all teams synced by Nais."), Privacy: new("closed")}).
			Return(nil, response(http.StatusUnprocessableEntity), errors.New("already exists")).Once()
		teams.EXPECT().GetTeamBySlug(ctx, "org", parentTeamSlug).
			Return(parent, response(http.StatusOK), nil).Once()
		r := &githubTeamReconciler{org: "org", teamsService: teams}
		team, err := r.getOrCreateParentTeam(ctx)
		require.NoError(t, err)
		require.Same(t, parent, team)
	})

	t.Run("lookup failure", func(t *testing.T) {
		teams := NewMockTeamsService(t)
		teams.EXPECT().GetTeamBySlug(ctx, "org", parentTeamSlug).
			Return(nil, nil, errors.New("unavailable")).Once()
		r := &githubTeamReconciler{org: "org", teamsService: teams}
		_, err := r.getOrCreateParentTeam(ctx)
		require.ErrorContains(t, err, "get GitHub parent team")
	})

	t.Run("creation failure", func(t *testing.T) {
		teams := NewMockTeamsService(t)
		teams.EXPECT().GetTeamBySlug(ctx, "org", parentTeamSlug).
			Return(nil, response(http.StatusNotFound), nil).Once()
		teams.EXPECT().CreateTeam(ctx, "org", github.NewTeam{Name: parentTeamSlug, Description: new("Parent team for all teams synced by Nais."), Privacy: new("closed")}).
			Return(nil, nil, errors.New("forbidden")).Once()
		r := &githubTeamReconciler{org: "org", teamsService: teams}
		_, err := r.getOrCreateParentTeam(ctx)
		require.ErrorContains(t, err, "create GitHub parent team")
	})
}

func TestSyncTeamParent(t *testing.T) {
	ctx := t.Context()
	naisTeam := &protoapi.Team{Slug: "team", Purpose: "purpose"}
	const parentID int64 = 123

	for _, tt := range []struct {
		name   string
		parent *github.Team
	}{
		{name: "no parent"},
		{name: "wrong parent", parent: &github.Team{ID: new(int64(456))}},
		{name: "correct parent", parent: &github.Team{ID: new(parentID)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			teams := NewMockTeamsService(t)
			team := &github.Team{Slug: new("team"), Description: new("purpose"), Privacy: new("closed"), Parent: tt.parent}
			if tt.name != "correct parent" {
				teams.EXPECT().EditTeamBySlug(ctx, "org", "team", github.NewTeam{
					Name: "team", Description: &naisTeam.Purpose, Privacy: new("closed"), ParentTeamID: new(parentID),
				}, false).Return(team, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil).Once()
			}
			r := &githubTeamReconciler{org: "org", teamsService: teams}
			require.NoError(t, r.syncTeamInfo(ctx, naisTeam, team, parentID))
		})
	}
}

func TestParentTeamSlugIsReserved(t *testing.T) {
	r := &githubTeamReconciler{}
	for _, team := range []*protoapi.Team{
		{Slug: parentTeamSlug},
		{Slug: "team", GithubTeamSlug: new(parentTeamSlug)},
	} {
		_, err := r.getOrCreateTeam(t.Context(), team, 123)
		require.ErrorContains(t, err, "reserved for the parent team")
	}
}

func TestReconcileStopsWithoutParent(t *testing.T) {
	for _, failure := range []string{"lookup", "creation"} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s failure, existing child %t", failure, existing), func(t *testing.T) {
				ctx := t.Context()
				log, _ := test.NewNullLogger()
				teams := NewMockTeamsService(t)
				r := &githubTeamReconciler{org: "org", teamsService: teams}
				if failure == "lookup" {
					teams.EXPECT().GetTeamBySlug(ctx, "org", parentTeamSlug).
						Return(nil, nil, errors.New("unavailable")).Once()
				} else {
					teams.EXPECT().GetTeamBySlug(ctx, "org", parentTeamSlug).
						Return(nil, &github.Response{Response: &http.Response{StatusCode: http.StatusNotFound}}, nil).Once()
					teams.EXPECT().CreateTeam(ctx, "org", github.NewTeam{
						Name: parentTeamSlug, Description: new("Parent team for all teams synced by Nais."), Privacy: new("closed"),
					}).
						Return(nil, nil, errors.New("forbidden")).Once()
				}

				naisTeam := &protoapi.Team{Slug: "team", Purpose: "purpose"}
				if existing {
					naisTeam.GithubTeamSlug = new("team")
				}

				client, server := apiclient.NewMockClient(t)
				server.Reconcilers.EXPECT().State(mock.Anything, mock.Anything).
					Return(&protoapi.GetReconcilerStateResponse{}, nil).Once()

				err := r.Reconcile(ctx, client, naisTeam, log)
				if failure == "lookup" {
					require.ErrorContains(t, err, "get GitHub parent team")
				} else {
					require.ErrorContains(t, err, "create GitHub parent team")
				}
			})
		}
	}
}
