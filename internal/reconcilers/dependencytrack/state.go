package dependencytrack_reconciler

import (
	"context"
	"encoding/json"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

type DependencyTrackState struct {
	TeamID  string   `json:"teamId"`
	Members []string `json:"members"`
}

func (r *reconciler) saveState(ctx context.Context, client *apiclient.APIClient, teamSlug string, st *DependencyTrackState) error {
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

func (r *reconciler) loadState(ctx context.Context, client *apiclient.APIClient, teamSlug string) (*DependencyTrackState, error) {
	resp, err := client.Reconcilers().State(ctx, &protoapi.GetReconcilerStateRequest{
		ReconcilerName: reconcilerName,
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return nil, err
	}

	st := DependencyTrackState{}
	if resp.State == nil {
		return &st, nil
	}
	if err := json.Unmarshal(resp.State.Value, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (r *reconciler) deleteState(ctx context.Context, client protoapi.ReconcilersClient, teamSlug string) error {
	_, err := client.DeleteState(ctx, &protoapi.DeleteReconcilerStateRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return err
	}

	return nil
}
