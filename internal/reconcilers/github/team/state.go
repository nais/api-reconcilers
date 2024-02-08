package github_team_reconciler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

const stateKeyRepo = "repo"

type GitHubState struct {
	Repositories []*GitHubRepository
}

type GitHubRepository struct {
	Name        string                        `json:"-"`
	Permissions []*GitHubRepositoryPermission `json:"permissions"`
	Archived    bool                          `json:"archived"`
	RoleName    string                        `json:"roleName"`
}

type GitHubRepositoryPermission struct {
	Name    string `json:"name"`
	Granted bool   `json:"granted"`
}

func (r *githubTeamReconciler) saveState(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, desiredGitHubTeamSlug string, desiredState *GitHubState) error {
	req := &protoapi.SaveReconcilerResourceRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       naisTeam.Slug,
	}

	for _, repo := range desiredState.Repositories {
		metadata, err := json.Marshal(repo)
		if err != nil {
			return err
		}
		req.Resources = append(req.Resources, &protoapi.NewReconcilerResource{
			Name:     stateKeyRepo,
			Value:    []byte(repo.Name),
			Metadata: metadata,
		})
	}

	if _, err := client.ReconcilerResources().Save(ctx, req); err != nil {
		return err
	}

	if naisTeam.GithubTeamSlug == nil || *naisTeam.GithubTeamSlug != desiredGitHubTeamSlug {
		_, err := client.Teams().SetTeamExternalReferences(ctx, &protoapi.SetTeamExternalReferencesRequest{
			Slug:           naisTeam.Slug,
			GithubTeamSlug: &desiredGitHubTeamSlug,
		})
		if err != nil {
			return fmt.Errorf("set GitHub team slug for team %q: %w", naisTeam.Slug, err)
		}
	}

	return nil
}

func (r *githubTeamReconciler) loadState(ctx context.Context, client *apiclient.APIClient, teamSlug string) (*GitHubState, error) {
	return getState(ctx, client.ReconcilerResources(), teamSlug)
}

func GetTeamRepositories(ctx context.Context, client protoapi.ReconcilerResourcesClient, teamSlug string) ([]*GitHubRepository, error) {
	state, err := getState(ctx, client, teamSlug)
	if err != nil {
		return nil, err
	}

	return state.Repositories, nil
}

func getState(ctx context.Context, client protoapi.ReconcilerResourcesClient, teamSlug string) (*GitHubState, error) {
	resp, err := client.List(ctx, &protoapi.ListReconcilerResourcesRequest{
		ReconcilerName: reconcilerName,
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return nil, err
	}

	s := &GitHubState{}
	for _, resource := range resp.Nodes {
		switch resource.Name {
		case stateKeyRepo:
			repo := &GitHubRepository{
				Name: string(resource.Value),
			}

			if resource.Metadata != nil {
				if err := json.Unmarshal(resource.Metadata, repo); err != nil {
					return nil, err
				}
				s.Repositories = append(s.Repositories, repo)
			}
		}
	}

	return s, nil
}
