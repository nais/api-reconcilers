package nais_namespace_reconciler

import (
	"context"
	"encoding/json"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

// state is a map of namespace names to unix timestamps
type state map[string]int64

func (r *naisNamespaceReconciler) saveState(ctx context.Context, client *apiclient.APIClient, teamSlug string, st state) error {
	j, err := json.Marshal(st)
	if err != nil {
		return err
	}

	_, err = client.Reconcilers().SaveState(ctx, &protoapi.SaveReconcilerStateRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
		Value:          j,
	})
	return err
}

func (r *naisNamespaceReconciler) loadState(ctx context.Context, client *apiclient.APIClient, teamSlug string) (state, error) {
	resp, err := client.Reconcilers().State(ctx, &protoapi.GetReconcilerStateRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return nil, err
	}

	st := state{}
	if resp.State == nil {
		return st, nil
	}
	if err := json.Unmarshal(resp.State.Value, &st); err != nil {
		return nil, err
	}
	return st, nil
}
