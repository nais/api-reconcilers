package dependencytrack_reconciler

import (
	"context"
	"encoding/json"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	st := DependencyTrackState{}
	resp, err := client.Reconcilers().State(ctx, &protoapi.GetReconcilerStateRequest{
		ReconcilerName: reconcilerName,
		TeamSlug:       teamSlug,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok && e.Code() == codes.NotFound {
			// special case: team does not yet have any state
			return &st, nil
		}
		return nil, err
	} else if resp.State == nil {
		return &st, nil
	} else if err := json.Unmarshal(resp.State.Value, &st); err != nil {
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
