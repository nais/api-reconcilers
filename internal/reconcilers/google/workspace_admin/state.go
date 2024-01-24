package google_workspace_admin_reconciler

import (
	"context"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

const (
	stateKeyGroupEmail = "groupEmail"
)

type googleWorkspaceState struct {
	groupEmail string
}

func (r *googleWorkspaceAdminReconciler) saveState(ctx context.Context, client *apiclient.APIClient, teamSlug string, state *googleWorkspaceState) error {
	req := &protoapi.SaveReconcilerResourceRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
		Resources: []*protoapi.NewReconcilerResource{
			{
				Name:  stateKeyGroupEmail,
				Value: state.groupEmail,
			},
		},
	}

	if _, err := client.ReconcilerResources().Save(ctx, req); err != nil {
		return err
	}

	return nil
}

func (r *googleWorkspaceAdminReconciler) loadState(ctx context.Context, client *apiclient.APIClient, teamSlug string) (*googleWorkspaceState, error) {
	resp, err := client.ReconcilerResources().List(ctx, &protoapi.ListReconcilerResourcesRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return nil, err
	}

	s := &googleWorkspaceState{}
	for _, resource := range resp.Nodes {
		switch resource.Name {
		case stateKeyGroupEmail:
			s.groupEmail = resource.Value
		}
	}

	return s, nil
}
