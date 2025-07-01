package dependencytrack_reconciler

import "github.com/nais/dependencytrack/pkg/dependencytrack"

type Client interface {
	dependencytrack.Client
}
