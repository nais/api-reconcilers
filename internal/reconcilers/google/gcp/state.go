package google_gcp_reconciler

import (
	"context"
	"strings"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

const (
	stateKeyProject = "project"

	envProjectIDSeparator = "::"
)

type googleGcpProjectState struct {
	projects map[string]string // env => projectID
}

func (r *googleGcpReconciler) saveState(ctx context.Context, client *apiclient.APIClient, teamSlug string, state *googleGcpProjectState) error {
	req := &protoapi.SaveReconcilerResourceRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	}

	for env, projectID := range state.projects {
		req.Resources = append(req.Resources, &protoapi.NewReconcilerResource{
			Name:  stateKeyProject,
			Value: env + envProjectIDSeparator + projectID,
		})
	}

	if _, err := client.ReconcilerResources().Save(ctx, req); err != nil {
		return err
	}

	return nil
}

func (r *googleGcpReconciler) loadState(ctx context.Context, client *apiclient.APIClient, teamSlug string) (*googleGcpProjectState, error) {
	resp, err := client.ReconcilerResources().List(ctx, &protoapi.ListReconcilerResourcesRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return nil, err
	}

	s := &googleGcpProjectState{
		projects: make(map[string]string),
	}
	for _, resource := range resp.Nodes {
		switch resource.Name {
		case stateKeyProject:
			parts := strings.Split(resource.Value, envProjectIDSeparator)
			if len(parts) != 2 {
				// TODO: Log?
				continue
			}

			s.projects[parts[0]] = parts[1]
		}
	}

	return s, nil
}

func (r *googleGcpReconciler) deleteState(ctx context.Context, client protoapi.ReconcilerResourcesClient, teamSlug string) error {
	_, err := client.Delete(ctx, &protoapi.DeleteReconcilerResourcesRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return err
	}

	return nil
}
