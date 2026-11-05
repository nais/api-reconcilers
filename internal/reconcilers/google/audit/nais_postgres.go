package audit

import (
	"context"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/iterator"
	"github.com/nais/api/pkg/apiclient/protoapi"
)

// naisPostgresEnvironments returns the set of environments where the team has
// at least one Nais Postgres database.
func naisPostgresEnvironments(ctx context.Context, client *apiclient.APIClient, teamSlug string) (map[string]bool, error) {
	envs := make(map[string]bool)

	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListDatabasesResponse, error) {
		return client.Databases().List(ctx, &protoapi.ListDatabasesRequest{Limit: limit, Offset: offset, TeamSlug: teamSlug})
	})

	for it.Next() {
		db := it.Value()
		if db.GetType() == protoapi.DatabaseType_NAIS_POSTGRES {
			envs[db.GetEnvironment()] = true
		}
	}

	return envs, it.Err()
}
