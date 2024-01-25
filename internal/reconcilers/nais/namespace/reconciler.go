package nais_namespace_reconciler

import (
	"context"
	"fmt"

	"cloud.google.com/go/pubsub"
	"github.com/google/uuid"
	"github.com/nais/api-reconcilers/internal/gcp"
	"github.com/nais/api-reconcilers/internal/google_token_source"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	"github.com/nais/api-reconcilers/internal/reconcilers/azure/group"
	"github.com/nais/api-reconcilers/internal/reconcilers/google/gcp"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/option"
)

const reconcilerName = "nais:namespace"

type OptFunc func(*naisNamespaceReconciler)

type naisNamespaceReconciler struct {
	azureEnabled              bool
	clusters                  gcp.Clusters
	cnrmServiceAccountID      string
	googleManagementProjectID string
	onpremClusters            []string
	pubsubClient              *pubsub.Client
	tenantDomain              string
}

func New(ctx context.Context, clusters gcp.Clusters, tenantDomain, googleManagementProjectID, cnrmServiceAccountID string, azureEnabled bool, onpremClusters []string, opts ...OptFunc) (reconcilers.Reconciler, error) {
	r := &naisNamespaceReconciler{
		azureEnabled:              azureEnabled,
		clusters:                  clusters,
		cnrmServiceAccountID:      cnrmServiceAccountID,
		googleManagementProjectID: googleManagementProjectID,
		onpremClusters:            onpremClusters,
		tenantDomain:              tenantDomain,
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.pubsubClient == nil {
		builder, err := google_token_source.New(googleManagementProjectID, tenantDomain)
		if err != nil {
			return nil, err
		}

		tokenSource, err := builder.GCP(ctx)
		if err != nil {
			return nil, fmt.Errorf("create token source: %w", err)
		}

		pubsubClient, err := pubsub.NewClient(ctx, googleManagementProjectID, option.WithTokenSource(tokenSource))
		if err != nil {
			return nil, fmt.Errorf("retrieve pubsub client: %w", err)
		}

		r.pubsubClient = pubsubClient
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

func (r *naisNamespaceReconciler) Reconfigure(_ context.Context, _ *apiclient.APIClient, _ logrus.FieldLogger) error {
	// TODO: Handle configuration change
	return nil
}

func (r *naisNamespaceReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	if naisTeam.GoogleGroupEmail == "" {
		return fmt.Errorf("no Google Workspace group exists for team %q yet", naisTeam.Slug)
	}

	state, err := r.loadState(ctx, client, naisTeam.Slug)
	if err != nil {
		return err
	}

	gcpProjects, err := google_gcp_reconciler.GetGcpProjects(ctx, client.ReconcilerResources(), naisTeam.Slug)
	if err != nil {
		return err
	}

	if len(gcpProjects) == 0 {
		return fmt.Errorf("no GCP project state exists for team %q yet", naisTeam.Slug)
	}

	azureGroupID, err := r.getAzureGroupID(ctx, client.ReconcilerResources(), naisTeam.Slug)
	if err != nil {
		return err
	}

	updateGcpProjectState := false

	resp, err := client.Teams().SlackAlertsChannels(ctx, &protoapi.SlackAlertsChannelsRequest{
		Slug: naisTeam.Slug,
	})
	if err != nil {
		return err
	}
	slackAlertsChannels := resp.Channels

	for _, cluster := range r.onpremClusters {
		gcpProjects[cluster] = ""
	}

	for environment, projectID := range gcpProjects {
		if !r.activeEnvironment(environment) {
			updateGcpProjectState = true
			log.WithField("environment", environment).Infof("environment from GCP project state is no longer active, will update state for the team")
			delete(gcpProjects, environment)
			continue
		}

		slackAlertsChannel := naisTeam.SlackChannel
		for _, c := range slackAlertsChannels {
			if c.Environment == environment {
				slackAlertsChannel = c.Channel
				break
			}
		}

		if err := r.createNamespace(ctx, naisTeam, environment, slackAlertsChannel, projectID, azureGroupID); err != nil {
			return fmt.Errorf("unable to create namespace for project %q in environment %q: %w", projectID, environment, err)
		}

		if _, requested := state.namespaces[environment]; !requested {
			state.namespaces[environment] = naisTeam.Slug
		}
	}

	if err := r.saveState(ctx, client, naisTeam.Slug, state); err != nil {
		return err
	}

	if updateGcpProjectState {
		// TODO: Persist GCP project state
		/*
			err = r.database.SetReconcilerStateForTeam(ctx, google_gcp_reconciler.Name, input.Team.Slug, gcpProjectState)
			if err != nil {
				log.WithError(err).Error("persisted GCP project state")
			}
		*/
	}

	return nil
}

func (r *naisNamespaceReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	state, err := r.loadState(ctx, client, naisTeam.Slug)
	if err != nil {
		return err
	}

	if len(state.namespaces) == 0 {
		log.Warnf("no namespaces for team, assume team has already been deleted")
		return r.deleteState(ctx, client.ReconcilerResources(), naisTeam.Slug)
	}

	var errors []error
	for environment := range state.namespaces {
		if !r.activeEnvironment(environment) {
			log.Infof("environment %q from namespace state is no longer active, will update state for the team", environment)
			delete(state.namespaces, environment)
			continue
		}

		if err := r.deleteNamespace(ctx, naisTeam.Slug, environment); err != nil {
			log.WithError(err).Errorf("delete namespace")
			errors = append(errors, err)
		} else {
			delete(state.namespaces, environment)
		}
	}

	if len(errors) == 0 {
		return r.deleteState(ctx, client.ReconcilerResources(), naisTeam.Slug)
	}

	if err := r.saveState(ctx, client, naisTeam.Slug, state); err != nil {
		log.WithError(err).Error("set reconciler state")
	}

	return fmt.Errorf("%d errors occured during namespace deletion", len(errors))
}

func (r *naisNamespaceReconciler) deleteNamespace(ctx context.Context, teamSlug, environment string) error {
	payload, err := deleteNamespacePayload(teamSlug)
	if err != nil {
		return err
	}

	topicName := naisdTopicPrefix + environment
	msg := &pubsub.Message{Data: payload}
	topic := r.pubsubClient.Topic(topicName)
	future := topic.Publish(ctx, msg)
	<-future.Ready()
	_, err = future.Get(ctx)
	topic.Stop()

	return err
}

func (r *naisNamespaceReconciler) createNamespace(ctx context.Context, naisTeam *protoapi.Team, environment, slackAlertsChannel, gcpProjectID string, azureGroupID uuid.UUID) error {
	payload, err := createNamespacePayload(naisTeam, gcpProjectID, slackAlertsChannel, r.cnrmServiceAccountID, azureGroupID)
	if err != nil {
		return err
	}

	topicName := naisdTopicPrefix + environment
	msg := &pubsub.Message{Data: payload}
	topic := r.pubsubClient.Topic(topicName)
	future := topic.Publish(ctx, msg)
	<-future.Ready()
	_, err = future.Get(ctx)
	topic.Stop()

	return err
}

func (r *naisNamespaceReconciler) getAzureGroupID(ctx context.Context, client protoapi.ReconcilerResourcesClient, teamSlug string) (uuid.UUID, error) {
	if !r.azureEnabled {
		return uuid.Nil, nil
	}
	return azure_group_reconciler.GetAzureGroupID(ctx, client, teamSlug)
}

func (r *naisNamespaceReconciler) activeEnvironment(environment string) bool {
	_, exists := r.clusters[environment]
	if exists {
		return true
	}
	for _, cluster := range r.onpremClusters {
		if cluster == environment {
			return true
		}
	}
	return false
}
