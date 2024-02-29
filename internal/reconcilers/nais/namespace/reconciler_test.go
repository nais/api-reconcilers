package nais_namespace_reconciler_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/pubsub/pstest"
	"github.com/google/uuid"
	nais_namespace_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/nais/namespace"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
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
		cnrmEmail                 = "nais-sa-cnrm@team-project-123.iam.gserviceaccount.com"
		slackChannel              = "#team-channel"
		googleGroupEmail          = "group-email@example.com"
		serviceAccountEmail       = "sa@example.com"
	)

	log, _ := test.NewNullLogger()

	t.Run("no google group email on team", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:         teamSlug,
			SlackChannel: slackChannel,
		}

		apiClient, _ := apiclient.NewMockClient(t)
		reconciler, err := nais_namespace_reconciler.New(ctx, serviceAccountEmail, tenantDomain, googleManagementProjectID, nais_namespace_reconciler.WithPubSubClient(noopPubsub()))
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
			GoogleGroupEmail: ptr.To(googleGroupEmail),
			AzureGroupId:     ptr.To("invalid"),
		}

		apiClient, _ := apiclient.NewMockClient(t)

		reconciler, err := nais_namespace_reconciler.New(ctx, serviceAccountEmail, tenantDomain, googleManagementProjectID, nais_namespace_reconciler.WithPubSubClient(noopPubsub()))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "invalid UUID") {
			t.Fatalf("unexpected error returned: %v", err)
		}
	})

	t.Run("no environments", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:             teamSlug,
			SlackChannel:     slackChannel,
			GoogleGroupEmail: ptr.To(googleGroupEmail),
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Reconcilers.EXPECT().
			State(mock.Anything, &protoapi.GetReconcilerStateRequest{TeamSlug: teamSlug, ReconcilerName: "nais:namespace"}).
			Return(nil, status.Error(codes.NotFound, "state not found")).
			Once()
		mockServer.Reconcilers.EXPECT().
			SaveState(mock.Anything, &protoapi.SaveReconcilerStateRequest{Value: []byte("{}"), TeamSlug: teamSlug, ReconcilerName: "nais:namespace"}).
			Return(&protoapi.SaveReconcilerStateResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Limit: 100, Offset: 0, Slug: teamSlug}).
			Return(&protoapi.ListTeamEnvironmentsResponse{}, nil).
			Once()

		reconciler, err := nais_namespace_reconciler.New(ctx, serviceAccountEmail, tenantDomain, googleManagementProjectID, nais_namespace_reconciler.WithPubSubClient(noopPubsub()))
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
			GoogleGroupEmail: ptr.To(googleGroupEmail),
			AzureGroupId:     ptr.To(uuid.New().String()),
		}

		srv, pubsubClient, closer := getPubsubServerAndClient(ctx, googleManagementProjectID, "naisd-console-"+environmentDev, "naisd-console-"+environmentProd)
		defer closer()

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Reconcilers.EXPECT().
			State(mock.Anything, &protoapi.GetReconcilerStateRequest{TeamSlug: teamSlug, ReconcilerName: "nais:namespace"}).
			Return(&protoapi.GetReconcilerStateResponse{}, nil).
			Once()
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
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(req *protoapi.CreateAuditLogsRequest) bool {
				return req.ReconcilerName == "nais:namespace" && req.Action == "nais:namespace:create-namespace"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Times(2)
		mockServer.Reconcilers.EXPECT().
			SaveState(mock.Anything, mock.MatchedBy(func(req *protoapi.SaveReconcilerStateRequest) bool {
				st := map[string]int64{}
				_ = json.Unmarshal(req.Value, &st)
				return len(st) == 2
			})).
			Return(&protoapi.SaveReconcilerStateResponse{}, nil).
			Once()

		reconciler, err := nais_namespace_reconciler.New(ctx, serviceAccountEmail, tenantDomain, googleManagementProjectID, nais_namespace_reconciler.WithPubSubClient(pubsubClient))
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

		if createNamespaceRequest.AzureGroupID != *naisTeam.AzureGroupId {
			t.Fatalf("expected Azure group ID to be %q, got %q", *naisTeam.AzureGroupId, createNamespaceRequest.AzureGroupID)
		}
	})

	t.Run("delete namespaces", func(t *testing.T) {
		naisTeam := &protoapi.Team{
			Slug:         teamSlug,
			SlackChannel: slackChannel,
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
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(req *protoapi.CreateAuditLogsRequest) bool {
				return req.ReconcilerName == "nais:namespace" && req.Action == "nais:namespace:delete-namespace"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		reconciler, err := nais_namespace_reconciler.New(ctx, serviceAccountEmail, tenantDomain, googleManagementProjectID, nais_namespace_reconciler.WithPubSubClient(pubsubClient))
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

func noopPubsub() *pubsub.Client {
	ctx, closer := context.WithCancel(context.Background())
	closer()

	client, err := pubsub.NewClient(
		ctx,
		"asdf",
		option.WithEndpoint("asdf"),
		option.WithoutAuthentication(),
	)
	if err != nil {
		panic(err)
	}
	return client
}
