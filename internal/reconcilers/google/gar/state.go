package google_gar_reconciler

import (
	"context"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

const (
	stateKeyRepositoryName = "repository_name"
)

type garState struct {
	repositoryName string
}

func (r *garReconciler) saveState(ctx context.Context, client *apiclient.APIClient, teamSlug string, state *garState) error {
	req := &protoapi.SaveReconcilerResourceRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
		Resources: []*protoapi.NewReconcilerResource{
			{
				Name:  stateKeyRepositoryName,
				Value: state.repositoryName,
			},
		},
	}

	if _, err := client.ReconcilerResources().Save(ctx, req); err != nil {
		return err
	}

	return nil
}

func (r *garReconciler) loadState(ctx context.Context, client *apiclient.APIClient, teamSlug string) (*garState, error) {
	resp, err := client.ReconcilerResources().List(ctx, &protoapi.ListReconcilerResourcesRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return nil, err
	}

	s := &garState{}
	for _, resource := range resp.Nodes {
		switch resource.Name {
		case stateKeyRepositoryName:
			s.repositoryName = resource.Value
		}
	}

	return s, nil
}

func (r *garReconciler) deleteState(ctx context.Context, client protoapi.ReconcilerResourcesClient, teamSlug string) error {
	_, err := client.Delete(ctx, &protoapi.DeleteReconcilerResourcesRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return err
	}

	return nil
}
