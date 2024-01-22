package github_team_reconciler

import (
	"context"
	"encoding/json"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

const (
	stateKeySlug = "slug"
	stateKeyRepo = "repo"
)

type gitHubState struct {
	Slug         string
	Repositories []*gitHubRepository
}

type gitHubRepository struct {
	Name        string                        `json:"-"`
	Permissions []*gitHubRepositoryPermission `json:"permissions"`
	Archived    bool                          `json:"archived"`
	RoleName    string                        `json:"roleName"`
}

type gitHubRepositoryPermission struct {
	Name    string `json:"name"`
	Granted bool   `json:"granted"`
}

func (r *githubTeamReconciler) saveState(ctx context.Context, client *apiclient.APIClient, teamSlug string, state *gitHubState) error {
	req := &protoapi.SaveReconcilerResourceRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
		Resources: []*protoapi.NewReconcilerResource{
			{
				Name:  stateKeySlug,
				Value: state.Slug,
			},
		},
	}

	for _, repo := range state.Repositories {
		metadata, err := json.Marshal(repo)
		if err != nil {
			return err

		}
		req.Resources = append(req.Resources, &protoapi.NewReconcilerResource{
			Name:     stateKeyRepo,
			Value:    repo.Name,
			Metadata: metadata,
		})
	}

	if _, err := client.ReconcilerResources().Save(ctx, req); err != nil {
		return err
	}

	return nil
}

func (r *githubTeamReconciler) loadState(ctx context.Context, client *apiclient.APIClient, teamSlug string) (*gitHubState, error) {
	resp, err := client.ReconcilerResources().List(ctx, &protoapi.ListReconcilerResourcesRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return nil, err
	}

	s := &gitHubState{}
	for _, resource := range resp.Nodes {
		switch resource.Name {
		case stateKeySlug:
			s.Slug = resource.Value
		case stateKeyRepo:
			repo := &gitHubRepository{
				Name: resource.Value,
			}

			if err := json.Unmarshal(resource.Metadata, repo); err != nil {
				return nil, err
			}
		}
	}

	return s, nil
}
