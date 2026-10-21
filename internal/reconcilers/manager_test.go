package reconcilers

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"go.opentelemetry.io/otel/metric/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type managerTestReconciler struct {
	name      string
	reconcile func(*protoapi.Team) error
	delete    func(*protoapi.Team) error
}

func (r *managerTestReconciler) Name() string {
	if r.name != "" {
		return r.name
	}
	return "manager-test"
}

func (r *managerTestReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{Name: r.Name()}
}

func (r *managerTestReconciler) Reconcile(_ context.Context, _ *apiclient.APIClient, team *protoapi.Team, _ logrus.FieldLogger) error {
	if r.reconcile != nil {
		return r.reconcile(team)
	}
	return nil
}

func (r *managerTestReconciler) Delete(_ context.Context, _ *apiclient.APIClient, team *protoapi.Team, _ logrus.FieldLogger) error {
	if r.delete != nil {
		return r.delete(team)
	}
	return nil
}

// Dispatch directly to the generated mocks: bufconn's transport goroutines
// otherwise outlive the synctest bubble and its virtual clock.
func managerTestClient(t *testing.T, servers *apiclient.MockServers) *apiclient.APIClient {
	t.Helper()
	client, err := apiclient.New("passthrough:///manager-test",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(func(ctx context.Context, _ string, req, reply any, _ *grpc.ClientConn, _ grpc.UnaryInvoker, _ ...grpc.CallOption) error {
			var response proto.Message
			var err error
			switch req := req.(type) {
			case *protoapi.GetTeamRequest:
				response, err = servers.Teams.Get(ctx, req)
			case *protoapi.ListReconcilersRequest:
				response, err = servers.Reconcilers.List(ctx, req)
			case *protoapi.SetReconcilerErrorForTeamRequest:
				response, err = servers.Reconcilers.SetReconcilerErrorForTeam(ctx, req)
			case *protoapi.RemoveReconcilerErrorForTeamRequest:
				response, err = servers.Reconcilers.RemoveReconcilerErrorForTeam(ctx, req)
			case *protoapi.SuccessfulTeamSyncRequest:
				response, err = servers.Reconcilers.SuccessfulTeamSync(ctx, req)
			case *protoapi.DeleteTeamRequest:
				response, err = servers.Teams.Delete(ctx, req)
			default:
				t.Errorf("unexpected API request %T", req)
				return status.Error(codes.Unimplemented, "unexpected API request")
			}
			if err == nil {
				proto.Merge(reply.(proto.Message), response)
			}
			return err
		}),
	)
	if err != nil {
		t.Fatalf("create API client: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close API client: %v", err)
		}
	})
	return client
}

func managerTestServers(t *testing.T) *apiclient.MockServers {
	t.Helper()
	client, servers := apiclient.NewMockClient(t)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close mock API client: %v", err)
		}
	})
	return servers
}

func newManagerTest(t *testing.T, servers *apiclient.MockServers, reconcilers ...Reconciler) *Manager {
	t.Helper()
	meter := noop.NewMeterProvider().Meter("manager-test")
	reconcilerTime, err := meter.Int64Histogram("reconciler")
	if err != nil {
		t.Fatalf("create reconciler histogram: %v", err)
	}
	teamTime, err := meter.Int64Histogram("team")
	if err != nil {
		t.Fatalf("create team histogram: %v", err)
	}
	log, _ := logrustest.NewNullLogger()
	m := &Manager{
		apiclient:            managerTestClient(t, servers),
		reconcilers:          reconcilers,
		syncQueue:            NewQueue(),
		log:                  log,
		metricReconcilerTime: reconcilerTime,
		metricReconcileTeam:  teamTime,
	}
	t.Cleanup(m.Close)
	return m
}

func runManagerTest(t *testing.T, m *Manager) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return cancel, done
}

func expectManagerTeam(servers *apiclient.MockServers, team *protoapi.Team, count int) {
	servers.Teams.EXPECT().Get(mock.Anything, &protoapi.GetTeamRequest{Slug: team.Slug}).
		Return(&protoapi.GetTeamResponse{Team: team}, nil).Times(count)
}

func expectManagerReconcilers(servers *apiclient.MockServers, count int) {
	servers.Reconcilers.EXPECT().List(mock.Anything, &protoapi.ListReconcilersRequest{Limit: 100}).
		Return(&protoapi.ListReconcilersResponse{Nodes: []*protoapi.Reconciler{{Name: "manager-test", Enabled: true}}}, nil).
		Times(count)
}

func expectManagerSuccess(servers *apiclient.MockServers, slug string, count int) {
	servers.Reconcilers.EXPECT().RemoveReconcilerErrorForTeam(mock.Anything,
		&protoapi.RemoveReconcilerErrorForTeamRequest{ReconcilerName: "manager-test", TeamSlug: slug}).
		Return(&protoapi.RemoveReconcilerErrorForTeamResponse{}, nil).Times(count)
	servers.Reconcilers.EXPECT().SuccessfulTeamSync(mock.Anything, &protoapi.SuccessfulTeamSyncRequest{TeamSlug: slug}).
		Return(&protoapi.SuccessfulTeamSyncResponse{}, nil).Times(count)
}

func TestManagerReconcilerOrder(t *testing.T) {
	for _, deleting := range []bool{false, true} {
		for _, failing := range []bool{false, true} {
			name := "reconcile"
			if deleting {
				name = "delete"
			}
			if failing {
				name += " with failure"
			}
			t.Run(name, func(t *testing.T) {
				servers := managerTestServers(t)
				team := &protoapi.Team{Slug: "ordered"}
				wantOrder := []string{"first", "second"}
				if deleting {
					team.DeleteKeyConfirmedAt = timestamppb.Now()
					wantOrder = []string{"second", "first"}
				}
				var order []string
				var reconcilers []Reconciler
				for _, name := range []string{"first", "second"} {
					operation := func(*protoapi.Team) error {
						order = append(order, name)
						if failing && name == wantOrder[0] {
							return errors.New("temporary failure")
						}
						return nil
					}
					r := &managerTestReconciler{name: name}
					if deleting {
						r.delete = operation
						r.reconcile = func(*protoapi.Team) error {
							t.Error("deleted team must not be reconciled")
							return nil
						}
					} else {
						r.reconcile = operation
						r.delete = func(*protoapi.Team) error {
							t.Error("active team must not be deleted")
							return nil
						}
					}
					reconcilers = append(reconcilers, r)
					if failing && name == wantOrder[0] {
						servers.Reconcilers.EXPECT().SetReconcilerErrorForTeam(mock.Anything,
							&protoapi.SetReconcilerErrorForTeamRequest{
								CorrelationId: "correlation", ReconcilerName: name,
								TeamSlug: team.Slug, ErrorMessage: "temporary failure",
							}).Return(&protoapi.SetReconcilerErrorForTeamResponse{}, nil).Once()
					} else {
						servers.Reconcilers.EXPECT().RemoveReconcilerErrorForTeam(mock.Anything,
							&protoapi.RemoveReconcilerErrorForTeamRequest{ReconcilerName: name, TeamSlug: team.Slug}).
							Return(&protoapi.RemoveReconcilerErrorForTeamResponse{}, nil).Once()
					}
				}
				m := newManagerTest(t, servers, reconcilers...)
				expectManagerTeam(servers, team, 1)
				servers.Reconcilers.EXPECT().List(mock.Anything, &protoapi.ListReconcilersRequest{Limit: 100}).
					Return(&protoapi.ListReconcilersResponse{Nodes: []*protoapi.Reconciler{
						{Name: "first", Enabled: true}, {Name: "second", Enabled: true},
					}}, nil).Once()
				if !failing {
					if deleting {
						servers.Teams.EXPECT().Delete(mock.Anything, &protoapi.DeleteTeamRequest{Slug: team.Slug}).
							Return(&protoapi.DeleteTeamResponse{}, nil).Once()
					} else {
						servers.Reconcilers.EXPECT().SuccessfulTeamSync(mock.Anything, &protoapi.SuccessfulTeamSyncRequest{TeamSlug: team.Slug}).
							Return(&protoapi.SuccessfulTeamSyncResponse{}, nil).Once()
					}
				}
				if got := m.syncTeam(t.Context(), ReconcileRequest{TeamSlug: team.Slug, CorrelationID: "correlation"}); got != !failing {
					t.Errorf("syncTeam() = %v, want %v", got, !failing)
				}
				if !slices.Equal(order, wantOrder) {
					t.Errorf("reconciler order = %v, want %v", order, wantOrder)
				}
				if got := m.reconcilers[0].Name(); got != "first" {
					t.Errorf("registered order changed: first reconciler = %q, want first", got)
				}
			})
		}
	}
}

func TestManagerWorkersDoNotProcessSameTeamConcurrently(t *testing.T) {
	servers := managerTestServers(t)
	synctest.Test(t, func(t *testing.T) {
		var attempts, ready atomic.Int32
		release := make(chan struct{})
		released := false
		defer func() {
			if !released {
				close(release)
			}
		}()
		r := &managerTestReconciler{reconcile: func(team *protoapi.Team) error {
			if team.Slug == "busy" {
				if attempts.Add(1) == 1 {
					<-release
				}
			} else {
				ready.Add(1)
			}
			return nil
		}}
		m := newManagerTest(t, servers, r)
		expectManagerTeam(servers, &protoapi.Team{Slug: "busy"}, 2)
		expectManagerTeam(servers, &protoapi.Team{Slug: "ready"}, 1)
		expectManagerReconcilers(servers, 3)
		expectManagerSuccess(servers, "busy", 2)
		expectManagerSuccess(servers, "ready", 1)
		if err := m.syncQueue.Add(ReconcileRequest{TeamSlug: "busy"}); err != nil {
			t.Fatal(err)
		}
		runManagerTest(t, m)
		runManagerTest(t, m)
		synctest.Wait()
		if got := attempts.Load(); got != 1 {
			t.Fatalf("attempts = %d, want 1", got)
		}
		if err := m.syncQueue.Add(ReconcileRequest{TeamSlug: "busy", CorrelationID: "new-event"}); err != nil {
			t.Fatal(err)
		}
		if err := m.syncQueue.Add(ReconcileRequest{TeamSlug: "ready"}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if got := ready.Load(); got != 1 {
			t.Errorf("other team's attempts = %d, want 1 while the busy team is active", got)
		}
		if got := attempts.Load(); got != 1 {
			t.Errorf("busy team's attempts = %d, want 1 until its active attempt finishes", got)
		}
		close(release)
		released = true
		synctest.Wait()
		if got := attempts.Load(); got != 2 {
			t.Errorf("busy team's attempts = %d, want 2 after its active attempt finishes", got)
		}
	})
}

func TestManagerDelayedRetryDoesNotBlockOtherTeams(t *testing.T) {
	servers := managerTestServers(t)
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var order []string
		var attempts []time.Time
		orderSnapshot := func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), order...)
		}
		r := &managerTestReconciler{reconcile: func(team *protoapi.Team) error {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, team.Slug)
			if team.Slug == "retry" {
				attempts = append(attempts, time.Now())
				if len(attempts) == 1 {
					return errors.New("operation pending")
				}
			}
			return nil
		}}
		m := newManagerTest(t, servers, r)
		expectManagerTeam(servers, &protoapi.Team{Slug: "retry"}, 2)
		expectManagerTeam(servers, &protoapi.Team{Slug: "ready"}, 1)
		expectManagerReconcilers(servers, 3)
		servers.Reconcilers.EXPECT().SetReconcilerErrorForTeam(mock.Anything,
			&protoapi.SetReconcilerErrorForTeamRequest{ReconcilerName: r.Name(), TeamSlug: "retry", ErrorMessage: "operation pending"}).
			Return(&protoapi.SetReconcilerErrorForTeamResponse{}, nil).Once()
		expectManagerSuccess(servers, "retry", 1)
		expectManagerSuccess(servers, "ready", 1)
		if err := m.syncQueue.Add(ReconcileRequest{TeamSlug: "retry"}); err != nil {
			t.Fatal(err)
		}
		if err := m.syncQueue.Add(ReconcileRequest{TeamSlug: "ready"}); err != nil {
			t.Fatal(err)
		}
		runManagerTest(t, m)
		synctest.Wait()
		if got, want := orderSnapshot(), []string{"retry", "ready"}; !slices.Equal(got, want) {
			t.Fatalf("initial order = %v, want %v", got, want)
		}
		time.Sleep(10*time.Second - time.Nanosecond)
		synctest.Wait()
		if got, want := orderSnapshot(), []string{"retry", "ready"}; !slices.Equal(got, want) {
			t.Fatalf("order before retry deadline = %v, want %v", got, want)
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if got, want := orderSnapshot(), []string{"retry", "ready", "retry"}; !slices.Equal(got, want) {
			t.Fatalf("order at retry deadline = %v, want %v", got, want)
		}
		mu.Lock()
		attemptSnapshot := append([]time.Time(nil), attempts...)
		mu.Unlock()
		if len(attemptSnapshot) != 2 {
			t.Fatalf("retry attempts = %d, want 2", len(attemptSnapshot))
		}
		if got := attemptSnapshot[1].Sub(attemptSnapshot[0]); got != 10*time.Second {
			t.Errorf("retry delay = %v, want 10s", got)
		}
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if got, want := orderSnapshot(), []string{"retry", "ready", "retry"}; !slices.Equal(got, want) {
			t.Errorf("order after success = %v, want %v", got, want)
		}
	})
}

func TestManagerRetriesDataFetchFailures(t *testing.T) {
	for _, stage := range []string{"team", "enabled reconcilers", "clear reconciler error persistence", "successful sync persistence"} {
		t.Run(stage, func(t *testing.T) {
			servers := managerTestServers(t)
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				m := newManagerTest(t, servers, &managerTestReconciler{reconcile: func(*protoapi.Team) error {
					calls.Add(1)
					return nil
				}})
				const slug = "retry-fetch"
				transient := status.Error(codes.Unavailable, "temporary API failure")
				if stage == "team" {
					servers.Teams.EXPECT().Get(mock.Anything, &protoapi.GetTeamRequest{Slug: slug}).
						Return(nil, transient).Once()
					expectManagerTeam(servers, &protoapi.Team{Slug: slug}, 1)
				} else {
					expectManagerTeam(servers, &protoapi.Team{Slug: slug}, 2)
				}
				if stage == "enabled reconcilers" {
					servers.Reconcilers.EXPECT().List(mock.Anything, &protoapi.ListReconcilersRequest{Limit: 100}).
						Return(nil, transient).Once()
				}
				if stage == "successful sync persistence" || stage == "clear reconciler error persistence" {
					expectManagerReconcilers(servers, 2)
				} else {
					expectManagerReconcilers(servers, 1)
				}
				if stage == "successful sync persistence" {
					servers.Reconcilers.EXPECT().RemoveReconcilerErrorForTeam(mock.Anything, mock.Anything).
						Return(&protoapi.RemoveReconcilerErrorForTeamResponse{}, nil).Once()
					servers.Reconcilers.EXPECT().SuccessfulTeamSync(mock.Anything, &protoapi.SuccessfulTeamSyncRequest{TeamSlug: slug}).
						Return(nil, transient).Once()
				} else if stage == "clear reconciler error persistence" {
					servers.Reconcilers.EXPECT().RemoveReconcilerErrorForTeam(mock.Anything,
						&protoapi.RemoveReconcilerErrorForTeamRequest{ReconcilerName: "manager-test", TeamSlug: slug}).
						Return(nil, transient).Once()
				}
				expectManagerSuccess(servers, slug, 1)
				if err := m.syncQueue.Add(ReconcileRequest{TeamSlug: slug}); err != nil {
					t.Fatal(err)
				}
				runManagerTest(t, m)
				synctest.Wait()
				before := 0
				if stage == "successful sync persistence" || stage == "clear reconciler error persistence" {
					before = 1
				}
				if got := int(calls.Load()); got != before {
					t.Fatalf("calls before retry = %d, want %d", got, before)
				}
				time.Sleep(10 * time.Second)
				synctest.Wait()
				if got := int(calls.Load()); got != before+1 {
					t.Fatalf("calls after retry = %d, want %d", got, before+1)
				}
				time.Sleep(10 * time.Minute)
				synctest.Wait()
				if got := int(calls.Load()); got != before+1 {
					t.Errorf("calls after success = %d, want %d", got, before+1)
				}
			})
		})
	}
}

func TestManagerNewEventSupersedesDelayedRetry(t *testing.T) {
	for _, failsAgain := range []bool{false, true} {
		name := "new attempt succeeds"
		if failsAgain {
			name = "new attempt fails"
		}
		t.Run(name, func(t *testing.T) {
			servers := managerTestServers(t)
			synctest.Test(t, func(t *testing.T) {
				var attempts atomic.Int32
				r := &managerTestReconciler{reconcile: func(*protoapi.Team) error {
					attempt := attempts.Add(1)
					if attempt == 1 || (attempt == 2 && failsAgain) {
						return errors.New("temporary failure")
					}
					return nil
				}}
				m := newManagerTest(t, servers, r)
				count := 2
				correlations := []string{"initial"}
				if failsAgain {
					count = 3
					correlations = append(correlations, "new-event")
				}
				expectManagerTeam(servers, &protoapi.Team{Slug: "updated"}, count)
				expectManagerReconcilers(servers, count)
				for _, correlation := range correlations {
					servers.Reconcilers.EXPECT().SetReconcilerErrorForTeam(mock.Anything,
						&protoapi.SetReconcilerErrorForTeamRequest{
							CorrelationId: correlation, ReconcilerName: r.Name(),
							TeamSlug: "updated", ErrorMessage: "temporary failure",
						}).Return(&protoapi.SetReconcilerErrorForTeamResponse{}, nil).Once()
				}
				expectManagerSuccess(servers, "updated", 1)
				if err := m.syncQueue.Add(ReconcileRequest{TeamSlug: "updated", CorrelationID: "initial"}); err != nil {
					t.Fatal(err)
				}
				runManagerTest(t, m)
				synctest.Wait()
				if got := attempts.Load(); got != 1 {
					t.Fatalf("initial attempts = %d, want 1", got)
				}
				time.Sleep(time.Second)
				if err := m.syncQueue.Add(ReconcileRequest{TeamSlug: "updated", CorrelationID: "new-event"}); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if got := attempts.Load(); got != 2 {
					t.Fatalf("attempts after new event = %d, want 2", got)
				}
				time.Sleep(9 * time.Second)
				synctest.Wait()
				if got := attempts.Load(); got != 2 {
					t.Fatalf("attempts at t=10s = %d, want 2; old retry must not run", got)
				}
				time.Sleep(time.Second)
				synctest.Wait()
				if got := attempts.Load(); got != int32(count) {
					t.Fatalf("attempts at t=11s = %d, want %d after reset backoff", got, count)
				}
				time.Sleep(10 * time.Minute)
				synctest.Wait()
				if got := attempts.Load(); got != int32(count) {
					t.Errorf("attempts after success = %d, want %d; no delayed retry should remain", got, count)
				}
			})
		})
	}
}

func TestManagerMissingTeamIsTerminal(t *testing.T) {
	servers := managerTestServers(t)
	synctest.Test(t, func(t *testing.T) {
		m := newManagerTest(t, servers, &managerTestReconciler{})
		servers.Teams.EXPECT().Get(mock.Anything, &protoapi.GetTeamRequest{Slug: "missing"}).
			Return(nil, status.Error(codes.NotFound, "team not found")).Once()
		if err := m.syncQueue.Add(ReconcileRequest{TeamSlug: "missing"}); err != nil {
			t.Fatal(err)
		}
		runManagerTest(t, m)
		synctest.Wait()
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if got := len(servers.Teams.Calls); got != 1 {
			t.Errorf("team API calls = %d, want 1", got)
		}
		if got := len(servers.Reconcilers.Calls); got != 0 {
			t.Errorf("reconciler API calls = %d, want 0 for a missing team", got)
		}
	})
}

func TestManagerRetriesDeletionFailures(t *testing.T) {
	for _, stage := range []string{"reconciler", "API persistence"} {
		t.Run(stage, func(t *testing.T) {
			servers := managerTestServers(t)
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				failure := errors.New("deletion pending")
				r := &managerTestReconciler{delete: func(*protoapi.Team) error {
					attempt := calls.Add(1)
					if stage == "reconciler" && attempt == 1 {
						return failure
					}
					return nil
				}, reconcile: func(*protoapi.Team) error {
					t.Error("deleted team must not be reconciled")
					return nil
				}}
				m := newManagerTest(t, servers, r)
				const slug = "deleted"
				expectManagerTeam(servers, &protoapi.Team{Slug: slug, DeleteKeyConfirmedAt: timestamppb.Now()}, 2)
				expectManagerReconcilers(servers, 2)
				successes := 1
				if stage == "reconciler" {
					servers.Reconcilers.EXPECT().SetReconcilerErrorForTeam(mock.Anything,
						&protoapi.SetReconcilerErrorForTeamRequest{ReconcilerName: r.Name(), TeamSlug: slug, ErrorMessage: failure.Error()}).
						Return(&protoapi.SetReconcilerErrorForTeamResponse{}, nil).Once()
				} else {
					successes = 2
					servers.Teams.EXPECT().Delete(mock.Anything, &protoapi.DeleteTeamRequest{Slug: slug}).
						Return(nil, failure).Once()
				}
				servers.Reconcilers.EXPECT().RemoveReconcilerErrorForTeam(mock.Anything,
					&protoapi.RemoveReconcilerErrorForTeamRequest{ReconcilerName: r.Name(), TeamSlug: slug}).
					Return(&protoapi.RemoveReconcilerErrorForTeamResponse{}, nil).Times(successes)
				servers.Teams.EXPECT().Delete(mock.Anything, &protoapi.DeleteTeamRequest{Slug: slug}).
					Return(&protoapi.DeleteTeamResponse{}, nil).Once()
				if err := m.syncQueue.Add(ReconcileRequest{TeamSlug: slug}); err != nil {
					t.Fatal(err)
				}
				runManagerTest(t, m)
				synctest.Wait()
				if got := calls.Load(); got != 1 {
					t.Fatalf("deletion attempts before retry = %d, want 1", got)
				}
				time.Sleep(10 * time.Second)
				synctest.Wait()
				if got := calls.Load(); got != 2 {
					t.Fatalf("deletion attempts after retry = %d, want 2", got)
				}
				time.Sleep(10 * time.Minute)
				synctest.Wait()
				if got := calls.Load(); got != 2 {
					t.Errorf("deletion attempts after success = %d, want 2", got)
				}
			})
		})
	}
}

func TestManagerCancellationShutsDownQueue(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "idle"
		if pending {
			name = "pending retry"
		}
		t.Run(name, func(t *testing.T) {
			servers := managerTestServers(t)
			synctest.Test(t, func(t *testing.T) {
				m := newManagerTest(t, servers, &managerTestReconciler{})
				if pending {
					servers.Teams.EXPECT().Get(mock.Anything, &protoapi.GetTeamRequest{Slug: "pending"}).
						Return(nil, status.Error(codes.Unavailable, "retry later")).Once()
					if err := m.syncQueue.Add(ReconcileRequest{TeamSlug: "pending"}); err != nil {
						t.Fatal(err)
					}
				}
				cancel, done := runManagerTest(t, m)
				synctest.Wait()
				cancel()
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("Run did not exit after context cancellation")
				}
				if err := m.syncQueue.Add(ReconcileRequest{TeamSlug: "after-cancel"}); err == nil {
					t.Fatal("expected adding to the canceled queue to fail")
				}
				_, shutdown := m.syncQueue.Get()
				if !shutdown {
					t.Fatal("expected queue shutdown after cancellation")
				}
				time.Sleep(10 * time.Minute)
				synctest.Wait()
			})
		})
	}
}
