package nais_namespace_reconciler_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/pubsub/pstest"
	"github.com/google/uuid"
	"github.com/nais/api-reconcilers/internal/gcp"
	nais_namespace_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/nais/namespace"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/utils/ptr"
)

func TestReconcile(t *testing.T) {
	ctx := context.Background()

	const (
		tenantDomain              = "example.com"
		googleManagementProjectID = "management-project-123"
		teamProjectID             = "team-project-123"
		teamSlug                  = "slug"
		environmentDev            = "dev"
		environmentProd           = "prod"
		clusterProjectIDDev       = "cluster-dev-123"
		clusterProjectIDProd      = "cluster-prod-123"
		cnrmEmail                 = "nais-sa-cnrm@team-project-123.iam.gserviceaccount.com"
		slackChannel              = "#team-channel"
		googleGroupEmail          = "group-email@example.com"
		azureEnabled              = true
		cnrmServiceAccountID      = "nais-sa-cnrm"
	)

	log, _ := test.NewNullLogger()
	noClusters := gcp.Clusters{}

	t.Run("no google group email on team", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:         teamSlug,
			SlackChannel: slackChannel,
		}

		apiClient, _ := apiclient.NewMockClient(t)
		reconciler, err := nais_namespace_reconciler.New(ctx, noClusters, tenantDomain, googleManagementProjectID, cnrmServiceAccountID, azureEnabled)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "no Google Workspace group exists") {
			t.Fatalf("unexpected error returned: %v", err)
		}
	})

	t.Run("invalid azure group ID", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:             teamSlug,
			SlackChannel:     slackChannel,
			GoogleGroupEmail: googleGroupEmail,
			AzureGroupId:     "invalid",
		}

		apiClient, _ := apiclient.NewMockClient(t)

		reconciler, err := nais_namespace_reconciler.New(ctx, noClusters, tenantDomain, googleManagementProjectID, cnrmServiceAccountID, azureEnabled)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "invalid UUID") {
			t.Fatalf("unexpected error returned: %v", err)
		}
	})

	t.Run("no GCP projects for team", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:             teamSlug,
			SlackChannel:     slackChannel,
			GoogleGroupEmail: googleGroupEmail,
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Limit: 100, Offset: 0, Slug: teamSlug}).
			Return(&protoapi.ListTeamEnvironmentsResponse{}, nil).
			Once()

		reconciler, err := nais_namespace_reconciler.New(ctx, noClusters, tenantDomain, googleManagementProjectID, cnrmServiceAccountID, azureEnabled)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatalf("unexpected error returned: %v", err)
		}
	})

	t.Run("create namespaces", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:             teamSlug,
			SlackChannel:     slackChannel,
			GoogleGroupEmail: googleGroupEmail,
			AzureGroupId:     uuid.New().String(),
		}

		clusters := gcp.Clusters{
			environmentDev: gcp.Cluster{
				TeamsFolderID: 123,
				ProjectID:     clusterProjectIDDev,
			},
			environmentProd: gcp.Cluster{
				TeamsFolderID: 123,
				ProjectID:     clusterProjectIDProd,
			},
		}

		srv, pubsubClient, closer := getPubsubServerAndClient(ctx, googleManagementProjectID, "naisd-console-"+environmentDev, "naisd-console-"+environmentProd)
		defer closer()

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Limit: 100, Offset: 0, Slug: teamSlug}).
			Return(&protoapi.ListTeamEnvironmentsResponse{
				Nodes: []*protoapi.TeamEnvironment{
					{
						EnvironmentName:    environmentDev,
						Gcp:                true,
						GcpProjectId:       ptr.To(teamProjectID),
						SlackAlertsChannel: "#env-channel",
					},
					{
						EnvironmentName:    environmentProd,
						Gcp:                true,
						GcpProjectId:       ptr.To(teamProjectID),
						SlackAlertsChannel: "#env-channel",
					},
				},
			}, nil).
			Once()

		reconciler, err := nais_namespace_reconciler.New(ctx, clusters, tenantDomain, googleManagementProjectID, cnrmServiceAccountID, azureEnabled, nais_namespace_reconciler.WithPubSubClient(pubsubClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatalf("unexpected error returned: %v", err)
		}

		msgs := srv.Messages()
		if len(msgs) != 2 {
			t.Fatalf("expected 2 messages, got %d", len(msgs))
		}

		publishRequest := &nais_namespace_reconciler.NaisdRequest{}
		_ = json.Unmarshal(msgs[0].Data, publishRequest)

		createNamespaceRequest := &nais_namespace_reconciler.NaisdCreateNamespace{}
		_ = json.Unmarshal(publishRequest.Data, createNamespaceRequest)

		if createNamespaceRequest.Name != teamSlug {
			t.Fatalf("expected name to be %q, got %q", teamSlug, createNamespaceRequest.Name)
		}

		if createNamespaceRequest.GcpProject != teamProjectID {
			t.Fatalf("expected GCP project ID to be %q, got %q", teamProjectID, createNamespaceRequest.GcpProject)
		}

		if createNamespaceRequest.GroupEmail != googleGroupEmail {
			t.Fatalf("expected group email to be %q, got %q", googleGroupEmail, createNamespaceRequest.GroupEmail)
		}

		if createNamespaceRequest.CNRMEmail != cnrmEmail {
			t.Fatalf("expected CNRM email to be %q, got %q", cnrmEmail, createNamespaceRequest.CNRMEmail)
		}

		if expected := "#env-channel"; createNamespaceRequest.SlackAlertsChannel != expected {
			t.Fatalf("expected slack alerts channel to be %q, got %q", expected, createNamespaceRequest.SlackAlertsChannel)
		}

		if createNamespaceRequest.AzureGroupID != naisTeam.AzureGroupId {
			t.Fatalf("expected Azure group ID to be %q, got %q", naisTeam.AzureGroupId, createNamespaceRequest.AzureGroupID)
		}
	})

	t.Run("delete namespaces", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:         teamSlug,
			SlackChannel: slackChannel,
		}

		clusters := gcp.Clusters{
			environmentDev: gcp.Cluster{
				TeamsFolderID: 123,
				ProjectID:     clusterProjectIDDev,
			},
		}

		srv, pubsubClient, closer := getPubsubServerAndClient(ctx, googleManagementProjectID, "naisd-console-"+environmentDev)
		defer closer()

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Limit: 100, Offset: 0, Slug: teamSlug}).
			Return(&protoapi.ListTeamEnvironmentsResponse{
				Nodes: []*protoapi.TeamEnvironment{
					{
						EnvironmentName: environmentDev,
					},
				},
			}, nil).
			Once()

		reconciler, err := nais_namespace_reconciler.New(ctx, clusters, tenantDomain, googleManagementProjectID, cnrmServiceAccountID, azureEnabled, nais_namespace_reconciler.WithPubSubClient(pubsubClient))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Delete(ctx, apiClient, naisTeam, log); err != nil {
			t.Fatalf("unexpected error returned: %v", err)
		}

		msgs := srv.Messages()
		if len(msgs) != 1 {
			t.Fatalf("expected 1 message, got %d", len(msgs))
		}

		publishRequest := &nais_namespace_reconciler.NaisdRequest{}
		_ = json.Unmarshal(msgs[0].Data, publishRequest)

		deleteNamespaceRequest := &nais_namespace_reconciler.NaisdDeleteNamespace{}
		_ = json.Unmarshal(publishRequest.Data, deleteNamespaceRequest)

		if deleteNamespaceRequest.Name != teamSlug {
			t.Fatalf("expected name to be %q, got %q", teamSlug, deleteNamespaceRequest.Name)
		}
	})
}

func getPubsubServerAndClient(ctx context.Context, projectID string, topics ...string) (*pstest.Server, *pubsub.Client, func()) {
	srv := pstest.NewServer()
	client, _ := pubsub.NewClient(
		ctx,
		projectID,
		option.WithEndpoint(srv.Addr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)

	for _, topic := range topics {
		_, _ = client.CreateTopic(ctx, topic)
	}

	return srv, client, func() {
		_ = srv.Close()
		_ = client.Close()
	}
}
