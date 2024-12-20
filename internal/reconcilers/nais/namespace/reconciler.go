package nais_namespace_reconciler

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/google/uuid"
	"github.com/nais/api-reconcilers/internal/google_token_source"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/iterator"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/option"
	"k8s.io/utils/ptr"
)

const reconcilerName = "nais:namespace"

type OptFunc func(*naisNamespaceReconciler)

func WithPubSubClient(client *pubsub.Client) OptFunc {
	return func(r *naisNamespaceReconciler) {
		r.pubsubClient = client
	}
}

type naisNamespaceReconciler struct {
	googleManagementProjectID string
	pubsubClient              *pubsub.Client
	tenantDomain              string
}

func New(ctx context.Context, serviceAccountEmail, tenantDomain, googleManagementProjectID string, opts ...OptFunc) (reconcilers.Reconciler, error) {
	r := &naisNamespaceReconciler{
		googleManagementProjectID: googleManagementProjectID,
		tenantDomain:              tenantDomain,
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.pubsubClient == nil {
		ts, err := google_token_source.GcpTokenSource(ctx, serviceAccountEmail)
		if err != nil {
			return nil, fmt.Errorf("create token source: %w", err)
		}

		pubsubClient, err := pubsub.NewClient(ctx, googleManagementProjectID, option.WithTokenSource(ts))
		if err == nil {
			r.pubsubClient = pubsubClient
		}
	}

	return r, nil
}

func (r *naisNamespaceReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "NAIS namespace",
		Description: "Create NAIS namespaces for the Console teams.",
		MemberAware: false,
	}
}

func (r *naisNamespaceReconciler) Name() string {
	return reconcilerName
}

func (r *naisNamespaceReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	if naisTeam.GoogleGroupEmail == nil {
		return fmt.Errorf("no Google Workspace group exists for team %q yet", naisTeam.Slug)
	}

	azureGroupID := uuid.Nil
	if naisTeam.EntraIdGroupId != nil {
		id, err := uuid.Parse(*naisTeam.EntraIdGroupId)
		if err != nil {
			return fmt.Errorf("unable to parse Azure group ID: %w", err)
		}
		azureGroupID = id
	}

	updated, err := r.loadState(ctx, client, naisTeam.Slug)
	if err != nil {
		return fmt.Errorf("unable to load state: %w", err)
	}

	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})
	for it.Next() {
		env := it.Value()
		if err := r.createNamespace(ctx, naisTeam, env, azureGroupID); err != nil {
			return fmt.Errorf("unable to create namespace for project %q in environment %q: %w", ptr.Deref(env.GcpProjectId, "<no project ID>"), env.EnvironmentName, err)
		}

		updated[env.EnvironmentName] = time.Now().Unix()
	}

	if err := r.saveState(ctx, client, naisTeam.Slug, updated); err != nil {
		return fmt.Errorf("unable to save state: %w", err)
	}

	return it.Err()
}

func (r *naisNamespaceReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	var errors []error
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})
	for it.Next() {
		env := it.Value()
		if err := r.deleteNamespace(ctx, naisTeam.Slug, env.EnvironmentName); err != nil {
			log.WithError(err).Errorf("delete namespace")
			errors = append(errors, err)
		}
	}

	if len(errors) == 0 {
		return nil
	}

	return fmt.Errorf("%d errors occured during namespace deletion", len(errors))
}

func (r *naisNamespaceReconciler) deleteNamespace(ctx context.Context, teamSlug, environment string) error {
	payload, err := deleteNamespacePayload(teamSlug)
	if err != nil {
		return err
	}

	return r.publishMessage(ctx, environment, payload)
}

func (r *naisNamespaceReconciler) createNamespace(ctx context.Context, naisTeam *protoapi.Team, env *protoapi.TeamEnvironment, azureGroupID uuid.UUID) error {
	payload, err := createNamespacePayload(naisTeam, env, azureGroupID)
	if err != nil {
		return err
	}

	return r.publishMessage(ctx, env.EnvironmentName, payload)
}

func (r *naisNamespaceReconciler) publishMessage(ctx context.Context, env string, payload []byte) error {
	topicName := naisdTopicPrefix + env
	msg := &pubsub.Message{Data: payload}
	topic := r.pubsubClient.Topic(topicName)
	future := topic.Publish(ctx, msg)
	<-future.Ready()
	_, err := future.Get(ctx)
	topic.Stop()

	return err
}
