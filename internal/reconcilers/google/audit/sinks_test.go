package audit

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	logging "cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/logging/apiv2/loggingpb"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

func TestIsManagedSink(t *testing.T) {
	r := &auditLogReconciler{}
	longTeam := strings.Repeat("t", 60)
	longEnv := strings.Repeat("e", 60)

	tests := []struct {
		name     string
		sinkName string
		team     string
		env      string
		expected bool
	}{
		{"sql audit sink", "sql-audit-sink-myteam-prod", "myteam", "prod", true},
		{"nais postgres audit sink", "npg-audit-sink-myteam-prod", "myteam", "prod", true},
		{"hashed nais postgres audit sink", GenerateNaisPostgresLogSinkName(longTeam, longEnv), longTeam, longEnv, true},
		{"hashed sql audit sink", GenerateLogSinkName(longTeam, longEnv), longTeam, longEnv, true},
		{"other team", "npg-audit-sink-otherteam-prod", "myteam", "prod", false},
		{"unmanaged sink", "some-other-sink", "myteam", "prod", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.isManagedSink(&loggingpb.LogSink{Name: tt.sinkName}, tt.team, tt.env); got != tt.expected {
				t.Errorf("isManagedSink(%q) = %v, expected %v", tt.sinkName, got, tt.expected)
			}
		})
	}
}

type fakeConfigServer struct {
	loggingpb.UnimplementedConfigServiceV2Server
	sinks            map[string]*loggingpb.LogSink
	buckets          map[string]*loggingpb.LogBucket
	writerIdentities map[string]string
}

func (f *fakeConfigServer) GetSink(_ context.Context, req *loggingpb.GetSinkRequest) (*loggingpb.LogSink, error) {
	if sink, ok := f.sinks[req.SinkName]; ok {
		return sink, nil
	}
	return nil, status.Error(codes.NotFound, "sink not found")
}

func (f *fakeConfigServer) CreateSink(_ context.Context, req *loggingpb.CreateSinkRequest) (*loggingpb.LogSink, error) {
	sink := proto.Clone(req.Sink).(*loggingpb.LogSink)
	sink.WriterIdentity = "serviceAccount:writer@example.com"
	if writerIdentity := f.writerIdentities[sink.Name]; writerIdentity != "" {
		sink.WriterIdentity = writerIdentity
	}
	f.sinks[req.Parent+"/sinks/"+sink.Name] = sink
	return sink, nil
}

func (f *fakeConfigServer) GetBucket(_ context.Context, req *loggingpb.GetBucketRequest) (*loggingpb.LogBucket, error) {
	if bucket, ok := f.buckets[req.Name]; ok {
		return bucket, nil
	}
	return nil, status.Error(codes.NotFound, "bucket not found")
}

func (f *fakeConfigServer) CreateBucket(_ context.Context, req *loggingpb.CreateBucketRequest) (*loggingpb.LogBucket, error) {
	bucket := proto.Clone(req.Bucket).(*loggingpb.LogBucket)
	bucket.Name = req.Parent + "/buckets/" + req.BucketId
	f.buckets[bucket.Name] = bucket
	return bucket, nil
}

func (f *fakeConfigServer) GetView(_ context.Context, req *loggingpb.GetViewRequest) (*loggingpb.LogView, error) {
	return &loggingpb.LogView{Name: req.Name}, nil
}

func newReconcilerWithFakeConfigServer(t *testing.T) (*auditLogReconciler, *fakeConfigServer) {
	t.Helper()

	fake := &fakeConfigServer{
		sinks:            map[string]*loggingpb.LogSink{},
		buckets:          map[string]*loggingpb.LogBucket{},
		writerIdentities: map[string]string{},
	}
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	loggingpb.RegisterConfigServiceV2Server(server, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial fake config server: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client, err := logging.NewConfigClient(context.Background(), option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("create config client: %v", err)
	}

	return &auditLogReconciler{
		services: &Services{LogConfigService: client},
		config:   Config{ProjectID: "management-project", Location: "europe-north1"},
	}, fake
}

func TestReconcileNaisPostgresCreatesExpectedSinksAndWriterPermissions(t *testing.T) {
	ctx := context.Background()

	for _, tt := range []struct {
		name        string
		sqlAudit    bool
		wantSinks   []string
		wantWriters []string
	}{
		{
			name:        "Nais Postgres only",
			wantSinks:   []string{"npg-audit-sink-myteam-prod"},
			wantWriters: []string{"serviceAccount:npg-writer@example.com"},
		},
		{
			name:        "Nais Postgres and SQL",
			sqlAudit:    true,
			wantSinks:   []string{"npg-audit-sink-myteam-prod", "sql-audit-sink-myteam-prod"},
			wantWriters: []string{"serviceAccount:npg-writer@example.com", "serviceAccount:sql-writer@example.com"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, fake := newReconcilerWithFakeConfigServer(t)
			fake.writerIdentities["npg-audit-sink-myteam-prod"] = "serviceAccount:npg-writer@example.com"
			fake.writerIdentities["sql-audit-sink-myteam-prod"] = "serviceAccount:sql-writer@example.com"

			iamPolicy := &cloudresourcemanager.Policy{}
			iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch {
				case strings.HasSuffix(req.URL.Path, ":getIamPolicy"):
					if err := json.NewEncoder(w).Encode(iamPolicy); err != nil {
						t.Errorf("encode IAM policy: %v", err)
					}
				case strings.HasSuffix(req.URL.Path, ":setIamPolicy"):
					var body cloudresourcemanager.SetIamPolicyRequest
					if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
						t.Errorf("decode IAM policy request: %v", err)
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					iamPolicy = body.Policy
					if err := json.NewEncoder(w).Encode(iamPolicy); err != nil {
						t.Errorf("encode updated IAM policy: %v", err)
					}
				default:
					http.NotFound(w, req)
				}
			}))
			t.Cleanup(iamServer.Close)
			var err error
			r.services.CloudResourceManagerService, err = cloudresourcemanager.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(iamServer.URL))
			if err != nil {
				t.Fatalf("create Cloud Resource Manager service: %v", err)
			}

			sqlResponse := &sqladmin.InstancesListResponse{}
			if tt.sqlAudit {
				sqlResponse.Items = []*sqladmin.DatabaseInstance{{
					Name: "test-instance",
					Settings: &sqladmin.Settings{DatabaseFlags: []*sqladmin.DatabaseFlags{
						{Name: "cloudsql.enable_pgaudit", Value: "on"},
					}},
				}}
			}
			sqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if err := json.NewEncoder(w).Encode(sqlResponse); err != nil {
					t.Errorf("encode SQL instances: %v", err)
				}
			}))
			t.Cleanup(sqlServer.Close)
			r.services.SQLAdminService, err = sqladmin.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(sqlServer.URL))
			if err != nil {
				t.Fatalf("create SQL Admin service: %v", err)
			}

			apiClient, mockServer := apiclient.NewMockClient(t)
			mockServer.Databases.EXPECT().
				List(mock.Anything, &protoapi.ListDatabasesRequest{TeamSlug: "myteam", Limit: 100}).
				Return(&protoapi.ListDatabasesResponse{
					Nodes: []*protoapi.Database{{
						Name:        "postgres",
						Environment: "prod",
						TeamSlug:    "myteam",
						Type:        protoapi.DatabaseType_NAIS_POSTGRES,
					}},
					PageInfo: &protoapi.PageInfo{TotalCount: 1},
				}, nil).
				Once()
			mockServer.Teams.EXPECT().
				Environments(mock.Anything, &protoapi.ListTeamEnvironmentsRequest{Slug: "myteam", Limit: 100}).
				Return(&protoapi.ListTeamEnvironmentsResponse{
					Nodes: []*protoapi.TeamEnvironment{{EnvironmentName: "prod", GcpProjectId: new("team-project")}},
				}, nil).
				Once()
			mockServer.Reconcilers.EXPECT().
				Config(mock.Anything, mock.Anything).
				Return(&protoapi.ConfigReconcilerResponse{
					Nodes: []*protoapi.ReconcilerConfig{{Key: "audit:retention_days", Value: "30"}},
				}, nil).
				Twice()

			log, _ := logrustest.NewNullLogger()
			if err := r.Reconcile(ctx, apiClient, &protoapi.Team{Slug: "myteam"}, log); err != nil {
				t.Fatalf("reconcile: %v", err)
			}

			if len(fake.sinks) != len(tt.wantSinks) {
				t.Fatalf("got sinks %v, want %v", fake.sinks, tt.wantSinks)
			}
			for _, name := range tt.wantSinks {
				if _, ok := fake.sinks["projects/team-project/sinks/"+name]; !ok {
					t.Errorf("expected sink %q, got sinks %v", name, fake.sinks)
				}
			}

			var writers []string
			for _, binding := range iamPolicy.Bindings {
				if binding.Role == "roles/logging.bucketWriter" {
					writers = append(writers, binding.Members...)
				}
			}
			for _, writer := range tt.wantWriters {
				if !slices.Contains(writers, writer) {
					t.Errorf("writer permission for %q not granted, got %v", writer, writers)
				}
			}
		})
	}
}

func TestCreateNaisPostgresLogSink(t *testing.T) {
	const (
		teamProjectID = "team-project"
		teamSlug      = "myteam"
		envName       = "prod"
		bucketName    = "my-bucket"
	)

	r, fake := newReconcilerWithFakeConfigServer(t)
	log, _ := logrustest.NewNullLogger()

	sinkName := GenerateNaisPostgresLogSinkName(teamSlug, envName)
	_, writerIdentity, err := r.createOrUpdateLogSinkIfNeeded(context.Background(), teamProjectID, teamSlug, envName, bucketName, sinkName, BuildNaisPostgresLogFilter(), log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if writerIdentity != "serviceAccount:writer@example.com" {
		t.Errorf("unexpected writer identity %q", writerIdentity)
	}

	sink, ok := fake.sinks["projects/team-project/sinks/npg-audit-sink-myteam-prod"]
	if !ok {
		t.Fatalf("expected Nais Postgres sink to be created, got sinks: %v", fake.sinks)
	}

	const wantFilter = `jsonPayload.logger="pgaudit"
AND jsonPayload.record.user_name=~".+@.+"`
	if sink.Filter != wantFilter {
		t.Errorf("filter = %q, want %q", sink.Filter, wantFilter)
	}

	const wantDestination = "logging.googleapis.com/projects/management-project/locations/europe-north1/buckets/my-bucket"
	if sink.Destination != wantDestination {
		t.Errorf("destination = %q, want %q", sink.Destination, wantDestination)
	}

	if _, _, err := r.createOrUpdateLogSinkIfNeeded(context.Background(), teamProjectID, teamSlug, envName, bucketName, sinkName, BuildNaisPostgresLogFilter(), log); err != nil {
		t.Fatalf("second reconcile should be a no-op, got: %v", err)
	}
}
