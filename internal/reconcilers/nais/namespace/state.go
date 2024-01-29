package nais_namespace_reconciler

import (
	"context"
	"strings"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

const (
	stateKeyNamespaces = "namespaces"

	envTeamSlugSeparator = "::"
)

type naisNamespaceState struct {
	namespaces map[string]string // env => teamSlug
}

func (r *naisNamespaceReconciler) saveState(ctx context.Context, client *apiclient.APIClient, teamSlug string, state *naisNamespaceState) error {
	req := &protoapi.SaveReconcilerResourceRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	}

	for env, ts := range state.namespaces {
		req.Resources = append(req.Resources, &protoapi.NewReconcilerResource{
			Name:  stateKeyNamespaces,
			Value: env + envTeamSlugSeparator + ts,
		})
	}

	if _, err := client.ReconcilerResources().Save(ctx, req); err != nil {
		return err
	}

	return nil
}

func (r *naisNamespaceReconciler) loadState(ctx context.Context, client *apiclient.APIClient, teamSlug string) (*naisNamespaceState, error) {
	resp, err := client.ReconcilerResources().List(ctx, &protoapi.ListReconcilerResourcesRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return nil, err
	}

	s := &naisNamespaceState{
		namespaces: make(map[string]string),
	}
	for _, resource := range resp.Nodes {
		switch resource.Name {
		case stateKeyNamespaces:
			parts := strings.Split(resource.Value, envTeamSlugSeparator)
			if len(parts) != 2 {
				continue
			}

			s.namespaces[parts[0]] = parts[1]
		}
	}

	return s, nil
}

func (r *naisNamespaceReconciler) deleteState(ctx context.Context, client protoapi.ReconcilerResourcesClient, teamSlug string) error {
	_, err := client.Delete(ctx, &protoapi.DeleteReconcilerResourcesRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	})
	if err != nil {
		return err
	}

	return nil
}
