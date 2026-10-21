package reconcilers

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })
	return client
}

func newManagerTest(t *testing.T, servers *apiclient.MockServers, reconcilers ...Reconciler) *Manager {
	t.Helper()
	meter := noop.NewMeterProvider().Meter("manager-test")
	reconcilerTime, err := meter.Int64Histogram("reconciler")
	require.NoError(t, err)
	teamTime, err := meter.Int64Histogram("team")
	require.NoError(t, err)
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
				unused, servers := apiclient.NewMockClient(t)
				t.Cleanup(func() { assert.NoError(t, unused.Close()) })
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
				assert.Equal(t, !failing, m.syncTeam(t.Context(), ReconcileRequest{TeamSlug: team.Slug, CorrelationID: "correlation"}))
				assert.Equal(t, wantOrder, order)
				assert.Equal(t, "first", m.reconcilers[0].Name(), "deletion must not mutate the registered order")
			})
		}
	}
}

func TestManagerWorkersDoNotProcessSameTeamConcurrently(t *testing.T) {
	unused, servers := apiclient.NewMockClient(t)
	t.Cleanup(func() { assert.NoError(t, unused.Close()) })
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
		require.NoError(t, m.syncQueue.Add(ReconcileRequest{TeamSlug: "busy"}))
		runManagerTest(t, m)
		runManagerTest(t, m)
		synctest.Wait()
		require.Equal(t, int32(1), attempts.Load())
		require.NoError(t, m.syncQueue.Add(ReconcileRequest{TeamSlug: "busy", CorrelationID: "new-event"}))
		require.NoError(t, m.syncQueue.Add(ReconcileRequest{TeamSlug: "ready"}))
		synctest.Wait()
		assert.Equal(t, int32(1), ready.Load(), "other worker must process a different team")
		assert.Equal(t, int32(1), attempts.Load(), "updated team must wait for its active attempt")
		close(release)
		released = true
		synctest.Wait()
		assert.Equal(t, int32(2), attempts.Load(), "updated team must run after its active attempt")
	})
}

func TestManagerDelayedRetryDoesNotBlockOtherTeams(t *testing.T) {
	unused, servers := apiclient.NewMockClient(t)
	t.Cleanup(func() { assert.NoError(t, unused.Close()) })
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
		require.NoError(t, m.syncQueue.Add(ReconcileRequest{TeamSlug: "retry"}))
		require.NoError(t, m.syncQueue.Add(ReconcileRequest{TeamSlug: "ready"}))
		runManagerTest(t, m)
		synctest.Wait()
		require.Equal(t, []string{"retry", "ready"}, orderSnapshot())
		time.Sleep(10*time.Second - time.Nanosecond)
		synctest.Wait()
		require.Equal(t, []string{"retry", "ready"}, orderSnapshot())
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		require.Equal(t, []string{"retry", "ready", "retry"}, orderSnapshot())
		mu.Lock()
		attemptSnapshot := append([]time.Time(nil), attempts...)
		mu.Unlock()
		require.Len(t, attemptSnapshot, 2)
		assert.Equal(t, 10*time.Second, attemptSnapshot[1].Sub(attemptSnapshot[0]))
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		assert.Equal(t, []string{"retry", "ready", "retry"}, orderSnapshot())
	})
}

func TestManagerRetriesDataFetchFailures(t *testing.T) {
	for _, stage := range []string{"team", "enabled reconcilers", "clear reconciler error persistence", "successful sync persistence"} {
		t.Run(stage, func(t *testing.T) {
			unused, servers := apiclient.NewMockClient(t)
			t.Cleanup(func() { assert.NoError(t, unused.Close()) })
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
				require.NoError(t, m.syncQueue.Add(ReconcileRequest{TeamSlug: slug}))
				runManagerTest(t, m)
				synctest.Wait()
				before := 0
				if stage == "successful sync persistence" || stage == "clear reconciler error persistence" {
					before = 1
				}
				require.Equal(t, before, int(calls.Load()))
				time.Sleep(10 * time.Second)
				synctest.Wait()
				require.Equal(t, before+1, int(calls.Load()))
				time.Sleep(10 * time.Minute)
				synctest.Wait()
				assert.Equal(t, before+1, int(calls.Load()))
			})
		})
	}
}

func TestManagerMissingTeamIsTerminal(t *testing.T) {
	unused, servers := apiclient.NewMockClient(t)
	t.Cleanup(func() { assert.NoError(t, unused.Close()) })
	synctest.Test(t, func(t *testing.T) {
		m := newManagerTest(t, servers, &managerTestReconciler{})
		servers.Teams.EXPECT().Get(mock.Anything, &protoapi.GetTeamRequest{Slug: "missing"}).
			Return(nil, status.Error(codes.NotFound, "team not found")).Once()
		require.NoError(t, m.syncQueue.Add(ReconcileRequest{TeamSlug: "missing"}))
		runManagerTest(t, m)
		synctest.Wait()
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		servers.Teams.AssertNumberOfCalls(t, "Get", 1)
		servers.Reconcilers.AssertNotCalled(t, "List", mock.Anything, mock.Anything)
	})
}

func TestManagerRetriesDeletionFailures(t *testing.T) {
	for _, stage := range []string{"reconciler", "API persistence"} {
		t.Run(stage, func(t *testing.T) {
			unused, servers := apiclient.NewMockClient(t)
			t.Cleanup(func() { assert.NoError(t, unused.Close()) })
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
				require.NoError(t, m.syncQueue.Add(ReconcileRequest{TeamSlug: slug}))
				runManagerTest(t, m)
				synctest.Wait()
				require.Equal(t, int32(1), calls.Load())
				time.Sleep(10 * time.Second)
				synctest.Wait()
				require.Equal(t, int32(2), calls.Load())
				time.Sleep(10 * time.Minute)
				synctest.Wait()
				assert.Equal(t, int32(2), calls.Load())
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
			unused, servers := apiclient.NewMockClient(t)
			t.Cleanup(func() { assert.NoError(t, unused.Close()) })
			synctest.Test(t, func(t *testing.T) {
				m := newManagerTest(t, servers, &managerTestReconciler{})
				if pending {
					servers.Teams.EXPECT().Get(mock.Anything, &protoapi.GetTeamRequest{Slug: "pending"}).
						Return(nil, status.Error(codes.Unavailable, "retry later")).Once()
					require.NoError(t, m.syncQueue.Add(ReconcileRequest{TeamSlug: "pending"}))
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
				require.Error(t, m.syncQueue.Add(ReconcileRequest{TeamSlug: "after-cancel"}))
				_, shutdown := m.syncQueue.Get()
				require.True(t, shutdown)
				time.Sleep(10 * time.Minute)
				synctest.Wait()
			})
		})
	}
}
