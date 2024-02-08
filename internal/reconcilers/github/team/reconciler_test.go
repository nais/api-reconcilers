package github_team_reconciler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v50/github"
	github_team_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/github/team"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/shurcooL/githubv4"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"k8s.io/utils/ptr"
)

func TestGitHubReconciler_getOrCreateTeam(t *testing.T) {
	ctx := context.Background()

	const (
		org                       = "org"
		teamSlug                  = "slug"
		teamPurpose               = "purpose"
		authEndpoint              = "https://auth"
		googleManagementProjectID = "some-project-id"
	)

	log, _ := test.NewNullLogger()

	t.Run("no existing state, github team available", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:    teamSlug,
			Purpose: teamPurpose,
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "github:team:create"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		mockServer.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			SetTeamExternalReferences(mock.Anything, mock.MatchedBy(func(req *protoapi.SetTeamExternalReferencesRequest) bool {
				return req.Slug == teamSlug && *req.GithubTeamSlug == teamSlug
			})).
			Return(&protoapi.SetTeamExternalReferencesResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{}, nil).
			Once()
		mockServer.ReconcilerResources.EXPECT().
			Save(mock.Anything, mock.MatchedBy(func(req *protoapi.SaveReconcilerResourceRequest) bool {
				if len(req.Resources) != 2 {
					return false
				}

				m1 := &github_team_reconciler.GitHubRepository{}
				m2 := &github_team_reconciler.GitHubRepository{}

				_ = json.Unmarshal(req.Resources[0].Metadata, m1)
				_ = json.Unmarshal(req.Resources[1].Metadata, m2)

				return string(req.Resources[0].Value) == "org/some-repo-a" &&
					string(req.Resources[1].Value) == "org/some-repo-b" &&
					m1.Archived == false &&
					m2.Archived == true &&
					m1.Permissions[0].Name == "admin" &&
					m1.Permissions[1].Name == "pull" &&
					m1.Permissions[2].Name == "push"
			})).
			Return(&protoapi.SaveReconcilerResourceResponse{}, nil).
			Once()

		graphClient := github_team_reconciler.NewMockGraphClient(t)
		teamsService := github_team_reconciler.NewMockTeamsService(t)
		teamsService.EXPECT().
			CreateTeam(ctx, org, github.NewTeam{Name: teamSlug, Description: ptr.To(teamPurpose), Privacy: ptr.To("closed")}).
			Return(
				&github.Team{Slug: ptr.To(teamSlug)},
				&github.Response{Response: &http.Response{StatusCode: http.StatusCreated}},
				nil,
			).
			Once()
		teamsService.EXPECT().
			ListTeamMembersBySlug(mock.Anything, org, teamSlug, mock.Anything).
			Return(
				[]*github.User{},
				&github.Response{Response: &http.Response{StatusCode: http.StatusOK}},
				nil,
			).
			Once()
		teamsService.EXPECT().
			ListTeamReposBySlug(ctx, org, teamSlug, mock.MatchedBy(func(opts *github.ListOptions) bool {
				return opts.Page == 0
			})).
			Return(
				[]*github.Repository{
					{
						FullName: ptr.To(org + "/some-repo-b"),
						Permissions: map[string]bool{
							"push":  true,
							"pull":  false,
							"admin": true,
						},
						Archived: ptr.To(true),
					},
				},
				&github.Response{Response: &http.Response{StatusCode: http.StatusOK}, NextPage: 1},
				nil,
			).
			Once()
		teamsService.EXPECT().
			ListTeamReposBySlug(ctx, org, teamSlug, mock.MatchedBy(func(opts *github.ListOptions) bool {
				return opts.Page == 1
			})).
			Return(
				[]*github.Repository{
					{
						FullName: ptr.To(org + "/some-repo-a"),
						Permissions: map[string]bool{
							"push":  true,
							"pull":  false,
							"admin": true,
						},
						Archived: ptr.To(false),
					},
				},
				&github.Response{Response: &http.Response{StatusCode: http.StatusOK}},
				nil,
			).
			Once()
		teamsService.EXPECT().
			EditTeamBySlug(mock.Anything, org, teamSlug, github.NewTeam{
				Name:        teamSlug,
				Description: ptr.To(teamPurpose),
				Privacy:     ptr.To("closed"),
			}, false).
			Return(&github.Team{}, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil).
			Once()
		teamsService.EXPECT().
			CreateOrUpdateIDPGroupConnectionsBySlug(
				mock.Anything,
				org,
				teamSlug,
				github.IDPGroupList{Groups: []*github.IDPGroup{}},
			).
			Return(&github.IDPGroupList{}, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil).
			Once()

		reconciler, err := github_team_reconciler.New(ctx, org, authEndpoint, googleManagementProjectID, github_team_reconciler.WithTeamsService(teamsService), github_team_reconciler.WithGraphClient(graphClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("no existing state, github team not available", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:    teamSlug,
			Purpose: teamPurpose,
		}

		graphClient := github_team_reconciler.NewMockGraphClient(t)
		teamsService := github_team_reconciler.NewMockTeamsService(t)
		teamsService.EXPECT().
			CreateTeam(ctx, org, github.NewTeam{Name: teamSlug, Description: ptr.To(teamPurpose), Privacy: ptr.To("closed")}).
			Return(nil, &github.Response{Response: &http.Response{StatusCode: http.StatusUnprocessableEntity}}, nil).
			Once()

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{}, nil).
			Once()

		reconciler, err := github_team_reconciler.New(ctx, org, authEndpoint, googleManagementProjectID, github_team_reconciler.WithTeamsService(teamsService), github_team_reconciler.WithGraphClient(graphClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err = reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "unable to create GitHub team") {
			t.Fatalf("expected error")
		}
	})

	t.Run("existing state, github team exists", func(t *testing.T) {
		gitHubSlug := "github-slug"
		naisTeam := &protoapi.Team{
			Slug:           teamSlug,
			Purpose:        teamPurpose,
			GithubTeamSlug: ptr.To(gitHubSlug),
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{}, nil).
			Once()
		mockServer.ReconcilerResources.EXPECT().
			Save(mock.Anything, mock.MatchedBy(func(req *protoapi.SaveReconcilerResourceRequest) bool {
				return len(req.Resources) == 0
			})).
			Return(&protoapi.SaveReconcilerResourceResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{}, nil).
			Once()

		graphClient := github_team_reconciler.NewMockGraphClient(t)
		teamsService := github_team_reconciler.NewMockTeamsService(t)
		teamsService.EXPECT().
			GetTeamBySlug(ctx, org, gitHubSlug).
			Return(&github.Team{Slug: ptr.To(gitHubSlug)}, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil).
			Once()
		teamsService.EXPECT().
			ListTeamMembersBySlug(mock.Anything, org, gitHubSlug, mock.Anything).
			Return([]*github.User{}, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil).
			Once()
		teamsService.EXPECT().
			ListTeamReposBySlug(ctx, org, gitHubSlug, mock.Anything).
			Return([]*github.Repository{}, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil).
			Once()
		teamsService.EXPECT().
			EditTeamBySlug(mock.Anything, org, gitHubSlug, github.NewTeam{
				Name:        gitHubSlug,
				Description: ptr.To(teamPurpose),
				Privacy:     ptr.To("closed"),
			}, false).
			Return(&github.Team{}, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil).
			Once()
		teamsService.EXPECT().
			CreateOrUpdateIDPGroupConnectionsBySlug(mock.Anything, org, gitHubSlug, github.IDPGroupList{Groups: []*github.IDPGroup{}}).
			Return(&github.IDPGroupList{}, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil).
			Once()

		reconciler, err := github_team_reconciler.New(ctx, org, authEndpoint, googleManagementProjectID, github_team_reconciler.WithTeamsService(teamsService), github_team_reconciler.WithGraphClient(graphClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("existing state, github team no longer exists", func(t *testing.T) {
		existingSlug := "existing-slug"
		naisTeam := &protoapi.Team{
			Slug:           teamSlug,
			Purpose:        teamPurpose,
			GithubTeamSlug: ptr.To(existingSlug),
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "github:team:create"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		mockServer.ReconcilerResources.EXPECT().
			Save(mock.Anything, mock.MatchedBy(func(req *protoapi.SaveReconcilerResourceRequest) bool {
				return len(req.Resources) == 0
			})).
			Return(&protoapi.SaveReconcilerResourceResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{}, nil).
			Once()

		graphClient := github_team_reconciler.NewMockGraphClient(t)
		teamsService := github_team_reconciler.NewMockTeamsService(t)
		teamsService.EXPECT().
			GetTeamBySlug(ctx, org, existingSlug).
			Return(nil, &github.Response{Response: &http.Response{StatusCode: http.StatusNotFound}}, nil).
			Once()
		teamsService.EXPECT().
			CreateTeam(ctx, org, github.NewTeam{Name: existingSlug, Description: ptr.To(teamPurpose), Privacy: ptr.To("closed")}).
			Return(&github.Team{Slug: ptr.To(existingSlug)}, &github.Response{Response: &http.Response{StatusCode: http.StatusCreated}}, nil).
			Once()
		teamsService.EXPECT().
			ListTeamMembersBySlug(mock.Anything, org, existingSlug, mock.Anything).
			Return([]*github.User{}, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil).
			Once()
		teamsService.EXPECT().
			ListTeamReposBySlug(ctx, org, existingSlug, mock.Anything).
			Return([]*github.Repository{}, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil).
			Once()
		teamsService.EXPECT().
			EditTeamBySlug(mock.Anything, org, existingSlug, github.NewTeam{
				Name:        existingSlug,
				Description: ptr.To(teamPurpose),
				Privacy:     ptr.To("closed"),
			}, false).
			Return(&github.Team{}, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil).
			Once()
		teamsService.EXPECT().
			CreateOrUpdateIDPGroupConnectionsBySlug(mock.Anything, org, existingSlug, github.IDPGroupList{Groups: []*github.IDPGroup{}}).
			Return(&github.IDPGroupList{}, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil).
			Once()

		reconciler, err := github_team_reconciler.New(ctx, org, authEndpoint, googleManagementProjectID, github_team_reconciler.WithTeamsService(teamsService), github_team_reconciler.WithGraphClient(graphClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestGitHubReconciler_Reconcile(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()

	const (
		org                       = "my-organization"
		teamSlug                  = "myteam"
		teamName                  = "myteam"
		teamPurpose               = "some purpose"
		createLogin               = "should-create"
		createEmail               = "should-create@example.com"
		keepLogin                 = "should-keep"
		keepEmail                 = "should-keep@example.com"
		removeLogin               = "should-remove"
		removeEmail               = "should-remove@example.com"
		authEndpoint              = "https://auth"
		googleManagementProjectID = "some-project-id"
	)

	httpOk := &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}

	t.Run("unable to load state from database", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:    teamSlug,
			Purpose: teamPurpose,
		}

		graphClient := github_team_reconciler.NewMockGraphClient(t)
		teamsService := github_team_reconciler.NewMockTeamsService(t)
		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(nil, fmt.Errorf("some error")).
			Once()

		reconciler, err := github_team_reconciler.New(ctx, org, authEndpoint, googleManagementProjectID, github_team_reconciler.WithTeamsService(teamsService), github_team_reconciler.WithGraphClient(graphClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "some error") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// Give the reconciler enough data to create an entire team from scratch,
	// remove members that shouldn't be present, and add members that should.
	t.Run("create everything from scratch", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:    teamSlug,
			Purpose: teamPurpose,
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "github:team:create"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "github:team:delete-member" && strings.Contains(r.Message, `Deleted member "should-remove"`)
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "github:team:add-member" && strings.Contains(r.Message, `Added member "should-create"`)
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		mockServer.ReconcilerResources.EXPECT().
			Save(mock.Anything, mock.MatchedBy(func(req *protoapi.SaveReconcilerResourceRequest) bool {
				return len(req.Resources) == 0
			})).
			Return(&protoapi.SaveReconcilerResourceResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			SetTeamExternalReferences(mock.Anything, mock.MatchedBy(func(req *protoapi.SetTeamExternalReferencesRequest) bool {
				return req.Slug == teamSlug && *req.GithubTeamSlug == teamSlug
			})).
			Return(&protoapi.SetTeamExternalReferencesResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{
				Nodes: []*protoapi.TeamMember{
					{User: &protoapi.User{Email: keepEmail}},
					{User: &protoapi.User{Email: createEmail}},
				},
			}, nil).
			Once()
		mockServer.Users.EXPECT().
			Get(mock.Anything, &protoapi.GetUserRequest{Email: removeEmail}).
			Return(&protoapi.GetUserResponse{
				User: &protoapi.User{Email: removeEmail, Name: removeLogin},
			}, nil).
			Once()

		teamsService := github_team_reconciler.NewMockTeamsService(t)
		teamsService.EXPECT().
			CreateTeam(mock.Anything, org, github.NewTeam{
				Name:        teamName,
				Description: ptr.To(teamPurpose),
				Privacy:     ptr.To("closed"),
			}).
			Return(
				&github.Team{Slug: ptr.To(teamName)},
				&github.Response{Response: &http.Response{StatusCode: http.StatusCreated}},
				nil,
			).
			Once()
		teamsService.EXPECT().
			EditTeamBySlug(mock.Anything, org, teamName, github.NewTeam{
				Name:        teamName,
				Description: ptr.To(teamPurpose),
				Privacy:     ptr.To("closed"),
			}, false).
			Return(
				&github.Team{},
				httpOk,
				nil,
			).Once()
		teamsService.EXPECT().
			ListTeamMembersBySlug(mock.Anything, org, teamName, mock.Anything).
			Return(
				[]*github.User{
					{Login: ptr.To(keepLogin)},
					{Login: ptr.To(removeLogin)},
				},
				httpOk,
				nil,
			).
			Once()
		teamsService.EXPECT().
			AddTeamMembershipBySlug(mock.Anything, org, teamName, createLogin, mock.Anything).
			Return(
				&github.Membership{
					User: &github.User{
						Login: ptr.To(createLogin),
					},
				},
				httpOk,
				nil,
			).
			Once()
		teamsService.EXPECT().
			RemoveTeamMembershipBySlug(mock.Anything, org, teamName, removeLogin).
			Return(
				&github.Response{
					Response: &http.Response{
						StatusCode: http.StatusNoContent,
					},
				},
				nil,
			).
			Once()
		teamsService.EXPECT().
			CreateOrUpdateIDPGroupConnectionsBySlug(mock.Anything, org, teamName, github.IDPGroupList{Groups: []*github.IDPGroup{}}).
			Return(
				&github.IDPGroupList{},
				httpOk,
				nil,
			).Once()
		teamsService.EXPECT().
			ListTeamReposBySlug(ctx, org, teamName, mock.Anything).
			Return(
				[]*github.Repository{},
				httpOk,
				nil,
			).
			Once()

		graphClient := github_team_reconciler.NewMockGraphClient(t)
		graphClient.EXPECT().
			Query(mock.Anything, mock.Anything, map[string]interface{}{"org": githubv4.String(org), "login": githubv4.String(removeLogin)}).
			Run(func(_ context.Context, q interface{}, v map[string]interface{}) {
				query := q.(*github_team_reconciler.LookupGitHubSamlUserByGitHubUsername)
				query.Organization.SamlIdentityProvider.ExternalIdentities.Nodes = []github_team_reconciler.ExternalIdentity{
					{SamlIdentity: github_team_reconciler.ExternalIdentitySamlAttributes{Username: removeEmail}},
				}
			}).
			Once().
			Return(nil)
		graphClient.EXPECT().
			Query(mock.Anything, mock.Anything, map[string]interface{}{"org": githubv4.String(org), "username": githubv4.String(keepEmail)}).
			Run(func(_ context.Context, q interface{}, v map[string]interface{}) {
				query := q.(*github_team_reconciler.LookupGitHubSamlUserByEmail)
				query.Organization.SamlIdentityProvider.ExternalIdentities.Nodes = []github_team_reconciler.ExternalIdentity{
					{User: github_team_reconciler.GitHubUser{Login: keepLogin}},
				}
			}).
			Once().
			Return(nil)
		graphClient.EXPECT().
			Query(mock.Anything, mock.Anything, map[string]interface{}{"org": githubv4.String(org), "username": githubv4.String(createEmail)}).
			Run(func(_ context.Context, q interface{}, v map[string]interface{}) {
				query := q.(*github_team_reconciler.LookupGitHubSamlUserByEmail)
				query.Organization.SamlIdentityProvider.ExternalIdentities.Nodes = []github_team_reconciler.ExternalIdentity{
					{User: github_team_reconciler.GitHubUser{Login: createLogin}},
				}
			}).
			Once().
			Return(nil)

		reconciler, err := github_team_reconciler.New(ctx, org, authEndpoint, googleManagementProjectID, github_team_reconciler.WithTeamsService(teamsService), github_team_reconciler.WithGraphClient(graphClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("GetTeamBySlug error", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:           teamSlug,
			Purpose:        teamPurpose,
			GithubTeamSlug: ptr.To("slug-from-state"),
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.ReconcilerResources.EXPECT().
			List(mock.Anything, &protoapi.ListReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(&protoapi.ListReconcilerResourcesResponse{}, nil).
			Once()

		graphClient := github_team_reconciler.NewMockGraphClient(t)
		teamsService := github_team_reconciler.NewMockTeamsService(t)
		teamsService.EXPECT().
			GetTeamBySlug(mock.Anything, org, "slug-from-state").
			Return(nil, &github.Response{
				Response: &http.Response{
					StatusCode: http.StatusTeapot,
					Status:     "418: I'm a teapot",
					Body:       io.NopCloser(strings.NewReader("this is a body")),
				},
			}, nil).
			Once()

		reconciler, err := github_team_reconciler.New(ctx, org, authEndpoint, googleManagementProjectID, github_team_reconciler.WithTeamsService(teamsService), github_team_reconciler.WithGraphClient(graphClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "server error from GitHub: 418") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestGitHubReconciler_Delete(t *testing.T) {
	ctx := context.Background()

	const (
		org                       = "my-organization"
		teamSlug                  = "myteam"
		authEndpoint              = "https://auth"
		googleManagementProjectID = "some-project-id"
	)

	log, hook := test.NewNullLogger()

	t.Run("no GitHubTeamSlug on team instance", func(t *testing.T) {
		defer hook.Reset()

		naisTeam := &protoapi.Team{
			Slug: teamSlug,
		}

		graphClient := github_team_reconciler.NewMockGraphClient(t)
		teamsService := github_team_reconciler.NewMockTeamsService(t)
		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.ReconcilerResources.EXPECT().
			Delete(mock.Anything, &protoapi.DeleteReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(&protoapi.DeleteReconcilerResourcesResponse{}, nil).
			Once()

		reconciler, err := github_team_reconciler.New(ctx, org, authEndpoint, googleManagementProjectID, github_team_reconciler.WithTeamsService(teamsService), github_team_reconciler.WithGraphClient(graphClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Delete(ctx, apiClient, naisTeam, log); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(hook.Entries) != 1 {
			t.Errorf("expected one log entry, got %d", len(hook.Entries))
		}

		if !strings.Contains(hook.LastEntry().Message, "missing slug in reconciler state") {
			t.Errorf("unexpected log message: %s", hook.LastEntry().Message)
		}
	})

	t.Run("GitHub API client fails", func(t *testing.T) {
		gitHubSlug := "github-slug"
		naisTeam := &protoapi.Team{
			Slug:           teamSlug,
			GithubTeamSlug: ptr.To(gitHubSlug),
		}

		graphClient := github_team_reconciler.NewMockGraphClient(t)
		teamsService := github_team_reconciler.NewMockTeamsService(t)
		teamsService.EXPECT().
			DeleteTeamBySlug(ctx, org, gitHubSlug).
			Return(nil, fmt.Errorf("some error")).
			Once()

		apiClient, _ := apiclient.NewMockClient(t)

		reconciler, err := github_team_reconciler.New(ctx, org, authEndpoint, googleManagementProjectID, github_team_reconciler.WithTeamsService(teamsService), github_team_reconciler.WithGraphClient(graphClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Delete(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "delete GitHub team") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("unexpected response from GitHub API", func(t *testing.T) {
		gitHubSlug := "github-slug"
		naisTeam := &protoapi.Team{
			Slug:           teamSlug,
			GithubTeamSlug: ptr.To(gitHubSlug),
		}

		graphClient := github_team_reconciler.NewMockGraphClient(t)
		teamsService := github_team_reconciler.NewMockTeamsService(t)
		teamsService.EXPECT().
			DeleteTeamBySlug(ctx, org, gitHubSlug).
			Return(
				&github.Response{
					Response: &http.Response{
						StatusCode: http.StatusOK,
						Status:     "200: OK",
						Body:       io.NopCloser(strings.NewReader("body")),
					},
				},
				nil,
			).
			Once()

		apiClient, _ := apiclient.NewMockClient(t)

		reconciler, err := github_team_reconciler.New(ctx, org, authEndpoint, googleManagementProjectID, github_team_reconciler.WithTeamsService(teamsService), github_team_reconciler.WithGraphClient(graphClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Delete(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "unexpected server response from GitHub") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("successful delete", func(t *testing.T) {
		gitHubSlug := "github-slug"
		naisTeam := &protoapi.Team{
			Slug:           teamSlug,
			GithubTeamSlug: ptr.To(gitHubSlug),
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.ReconcilerResources.EXPECT().
			Delete(mock.Anything, &protoapi.DeleteReconcilerResourcesRequest{ReconcilerName: "github:team", TeamSlug: teamSlug}).
			Return(&protoapi.DeleteReconcilerResourcesResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(req *protoapi.CreateAuditLogsRequest) bool {
				return req.Action == "github:team:delete"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		graphClient := github_team_reconciler.NewMockGraphClient(t)
		teamsService := github_team_reconciler.NewMockTeamsService(t)
		teamsService.EXPECT().
			DeleteTeamBySlug(ctx, org, gitHubSlug).
			Return(
				&github.Response{
					Response: &http.Response{
						StatusCode: http.StatusNoContent,
						Status:     "204: No Content",
						Body:       io.NopCloser(strings.NewReader("")),
					},
				},
				nil,
			).
			Once()

		reconciler, err := github_team_reconciler.New(ctx, org, authEndpoint, googleManagementProjectID, github_team_reconciler.WithTeamsService(teamsService), github_team_reconciler.WithGraphClient(graphClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Delete(ctx, apiClient, naisTeam, log); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
