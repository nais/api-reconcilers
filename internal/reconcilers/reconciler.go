package reconcilers

import (
	"context"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
)

type Reconciler interface {
	Configuration() *protoapi.NewReconciler
	Name() string
	Reconfigure(ctx context.Context, client *apiclient.APIClient, log logrus.FieldLogger) error
	Reconcile(ctx context.Context, client *apiclient.APIClient, teamSlug string, log logrus.FieldLogger) error
	Delete(ctx context.Context, client *apiclient.APIClient, teamSlug string, log logrus.FieldLogger) error
}
