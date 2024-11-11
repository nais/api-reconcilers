package nais_namespace_reconciler

import (
	"context"
	"encoding/json"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	st := state{}
	resp, err := client.Reconcilers().State(ctx, &protoapi.GetReconcilerStateRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok && e.Code() == codes.NotFound {
			// special case: team does not yet have any state
			return st, nil
		}
		return nil, err
	} else if resp.State == nil {
		return st, nil
	} else if err := json.Unmarshal(resp.State.Value, &st); err != nil {
		return nil, err
	}
	return st, nil
}
