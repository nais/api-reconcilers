package nais_deploy_reconciler

import (
	"context"
	"time"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

const (
	stateKeyProvisioned = "provisioned"
)

type naisDeployState struct {
	provisioned time.Time
}

func (r *naisDeployReconciler) saveState(ctx context.Context, client *apiclient.APIClient, teamSlug string, state *naisDeployState) error {
	req := &protoapi.SaveReconcilerResourceRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
		Resources: []*protoapi.NewReconcilerResource{
			{
				Name:  stateKeyProvisioned,
				Value: state.provisioned.Format(time.RFC3339),
			},
		},
	}

	if _, err := client.ReconcilerResources().Save(ctx, req); err != nil {
		return err
	}

	return nil
}
