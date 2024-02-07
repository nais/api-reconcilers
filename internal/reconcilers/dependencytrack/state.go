package dependencytrack_reconciler

import (
	"context"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

const (
	stateKeyTeamID  = "team_id"
	stateKeyMembers = "members"
)

type dependencyTrackState struct {
	teamID  string
	members []string
}

func (r *reconciler) saveState(ctx context.Context, client *apiclient.APIClient, teamSlug string, state *dependencyTrackState) error {
	req := &protoapi.SaveReconcilerResourceRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
		Resources: []*protoapi.NewReconcilerResource{
			{
				Name:  stateKeyTeamID,
				Value: []byte(state.teamID),
			},
		},
	}

	for _, member := range state.members {
		req.Resources = append(req.Resources, &protoapi.NewReconcilerResource{
			Name:  stateKeyMembers,
			Value: []byte(member),
		})
	}

	if _, err := client.ReconcilerResources().Save(ctx, req); err != nil {
		return err
	}

	return nil
}

func (r *reconciler) loadState(ctx context.Context, client *apiclient.APIClient, teamSlug string) (*dependencyTrackState, error) {
	resp, err := client.ReconcilerResources().List(ctx, &protoapi.ListReconcilerResourcesRequest{
		ReconcilerName: reconcilerName,
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return nil, err
	}

	s := &dependencyTrackState{}
	for _, resource := range resp.Nodes {
		switch resource.Name {
		case stateKeyTeamID:
			s.teamID = string(resource.Value)
		case stateKeyMembers:
			s.members = append(s.members, string(resource.Value))
		}
	}

	return s, nil
}

func (r *reconciler) deleteState(ctx context.Context, client protoapi.ReconcilerResourcesClient, teamSlug string) error {
	_, err := client.Delete(ctx, &protoapi.DeleteReconcilerResourcesRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return err
	}

	return nil
}
