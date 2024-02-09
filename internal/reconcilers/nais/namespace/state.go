package nais_namespace_reconciler

import (
	"context"
	"strings"
	"time"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/iterator"
	"github.com/nais/api/pkg/protoapi"
)

type state map[string]time.Time

func (r *naisNamespaceReconciler) saveState(ctx context.Context, client *apiclient.APIClient, teamSlug string, updated state) error {
	req := &protoapi.SaveReconcilerResourceRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       teamSlug,
	}

	for env, ts := range updated {
		req.Resources = append(req.Resources, &protoapi.NewReconcilerResource{
			Name:  "timestamp",
			Value: []byte(env + "::" + ts.Format(time.RFC3339)),
		})
	}

	_, err := client.Reconcilers().SaveResources(ctx, req)
	return err
}

func (r *naisNamespaceReconciler) loadState(ctx context.Context, client *apiclient.APIClient, teamSlug string) (state, error) {
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListReconcilerResourcesResponse, error) {
		return client.Reconcilers().Resources(ctx, &protoapi.ListReconcilerResourcesRequest{Limit: limit, Offset: offset, TeamSlug: teamSlug, ReconcilerName: r.Name()})
	})
	updated := state{}
	for it.Next() {
		res := it.Value()
		switch res.Name {
		case "timestamp":
			parts := strings.Split(string(res.Value), "::")
			if len(parts) != 2 {
				continue
			}

			ts, err := time.Parse(time.RFC3339, parts[1])
			if err != nil {
				continue
			}

			updated[parts[0]] = ts
		}
	}

	return updated, nil
}
