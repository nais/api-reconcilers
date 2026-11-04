package audit

import (
	"context"
	"net"
	"strings"
	"testing"

	logging "cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/logging/apiv2/loggingpb"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"google.golang.org/api/option"
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
		{"cnpg audit sink", "cnpg-audit-sink-myteam-prod", "myteam", "prod", true},
		{"hashed cnpg audit sink", GenerateCNPGLogSinkName(longTeam, longEnv), longTeam, longEnv, true},
		{"hashed sql audit sink", GenerateLogSinkName(longTeam, longEnv), longTeam, longEnv, true},
		{"other team", "cnpg-audit-sink-otherteam-prod", "myteam", "prod", false},
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
	sinks map[string]*loggingpb.LogSink
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
	f.sinks[req.Parent+"/sinks/"+sink.Name] = sink
	return sink, nil
}

func newReconcilerWithFakeConfigServer(t *testing.T) (*auditLogReconciler, *fakeConfigServer) {
	t.Helper()

	fake := &fakeConfigServer{sinks: map[string]*loggingpb.LogSink{}}
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

func TestCreateCNPGLogSink(t *testing.T) {
	const (
		teamProjectID = "team-project"
		teamSlug      = "myteam"
		envName       = "prod"
		bucketName    = "my-bucket"
	)

	r, fake := newReconcilerWithFakeConfigServer(t)
	log, _ := logrustest.NewNullLogger()

	sinkName := GenerateCNPGLogSinkName(teamSlug, envName)
	_, writerIdentity, err := r.createOrUpdateLogSinkIfNeeded(context.Background(), teamProjectID, teamSlug, envName, bucketName, sinkName, BuildCNPGLogFilter(), log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if writerIdentity != "serviceAccount:writer@example.com" {
		t.Errorf("unexpected writer identity %q", writerIdentity)
	}

	sink, ok := fake.sinks["projects/team-project/sinks/cnpg-audit-sink-myteam-prod"]
	if !ok {
		t.Fatalf("expected CNPG sink to be created, got sinks: %v", fake.sinks)
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

	if _, _, err := r.createOrUpdateLogSinkIfNeeded(context.Background(), teamProjectID, teamSlug, envName, bucketName, sinkName, BuildCNPGLogFilter(), log); err != nil {
		t.Fatalf("second reconcile should be a no-op, got: %v", err)
	}
}
