package github_team_reconciler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

type GitHubState struct {
	Repositories []*GitHubRepository `json:"repositories"`
}

type GitHubRepository struct {
	Name        string                        `json:"name"`
	Permissions []*GitHubRepositoryPermission `json:"permissions"`
	Archived    bool                          `json:"archived"`
	RoleName    string                        `json:"roleName"`
}

type GitHubRepositoryPermission struct {
	Name    string `json:"name"`
	Granted bool   `json:"granted"`
}

func (r *githubTeamReconciler) saveState(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, desiredGitHubTeamSlug string, st *GitHubState) error {
	j, err := json.Marshal(st)
	if err != nil {
		return err
	}

	_, err = client.Reconcilers().SaveState(ctx, &protoapi.SaveReconcilerStateRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       naisTeam.Slug,
		Value:          j,
	})
	if err != nil {
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

	return err
}

func (r *githubTeamReconciler) loadState(ctx context.Context, client *apiclient.APIClient, teamSlug string) (*GitHubState, error) {
	return getState(ctx, client.Reconcilers(), teamSlug)
}

func GetTeamRepositories(ctx context.Context, client protoapi.ReconcilersClient, teamSlug string) ([]*GitHubRepository, error) {
	st, err := getState(ctx, client, teamSlug)
	if err != nil {
		return nil, err
	}

	return st.Repositories, nil
}

func getState(ctx context.Context, client protoapi.ReconcilersClient, teamSlug string) (*GitHubState, error) {
	resp, err := client.State(ctx, &protoapi.GetReconcilerStateRequest{
		ReconcilerName: reconcilerName,
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return nil, err
	}

	st := GitHubState{}
	if resp.State == nil {
		return &st, nil
	}

	if err := json.Unmarshal(resp.State.Value, &st); err != nil {
		return nil, err
	}
	return &st, nil
}
