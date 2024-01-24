package azure_group_reconciler

import (
	"context"

	"github.com/google/uuid"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

const stateKeyGroupID = "groupID"

type azureState struct {
	groupID uuid.UUID
}

func (r *azureGroupReconciler) saveState(ctx context.Context, client *apiclient.APIClient, teamSlug string, state *azureState) error {
	req := &protoapi.SaveReconcilerResourceRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
		Resources: []*protoapi.NewReconcilerResource{
			{
				Name:  stateKeyGroupID,
				Value: state.groupID.String(),
			},
		},
	}

	if _, err := client.ReconcilerResources().Save(ctx, req); err != nil {
		return err
	}

	return nil
}

func (r *azureGroupReconciler) loadState(ctx context.Context, client *apiclient.APIClient, teamSlug string) (*azureState, error) {
	resp, err := client.ReconcilerResources().List(ctx, &protoapi.ListReconcilerResourcesRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return nil, err
	}

	s := &azureState{}
	for _, resource := range resp.Nodes {
		switch resource.Name {
		case stateKeyGroupID:
			u, err := uuid.Parse(resource.Value)
			if err != nil {
				return nil, err
			}
			s.groupID = u
		}
	}

	return s, nil
}

func GetAzureGroupID(ctx context.Context, client protoapi.ReconcilerResourcesClient, teamSlug string) (uuid.UUID, error) {
	resp, err := client.List(ctx, &protoapi.ListReconcilerResourcesRequest{
		ReconcilerName: reconcilerName,
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return uuid.Nil, err
	}

	for _, resource := range resp.Nodes {
		switch resource.Name {
		case stateKeyGroupID:
			return uuid.Parse(resource.Value)
		}
	}

	return uuid.Nil, nil
}
