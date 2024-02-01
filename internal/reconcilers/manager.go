package reconcilers

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/iterator"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type ctxKey int

const (
	ctxCorrelationID ctxKey = iota
)

const reconcilerTimeout = time.Minute * 15

type Manager struct {
	apiclient   *apiclient.APIClient
	lock        sync.Mutex
	reconcilers []Reconciler
	log         logrus.FieldLogger

	metricReconcilerTime metric.Int64Histogram
	metricReconcileTeam  metric.Int64Histogram
	syncQueueChan        <-chan Input
	syncQueue            Queue

	teamsInFlight     map[string]struct{}
	teamsInFlightLock sync.Mutex
}

func NewManager(c *apiclient.APIClient, log logrus.FieldLogger) *Manager {
	meter := otel.Meter("reconcilers")
	recTime, err := meter.Int64Histogram("reconciler_duration", metric.WithDescription("Duration of a specific reconciler, regardless of team, in milliseconds"))
	if err != nil {
		log.WithError(err).Errorf("error when creating metric")
	}
	teamTime, err := meter.Int64Histogram("reconcile_team_duration", metric.WithDescription("Duration when reconciling an entire team, in milliseconds"))
	if err != nil {
		log.WithError(err).Errorf("error when creating metric")
	}

	queue, channel := NewQueue()
	return &Manager{
		apiclient:            c,
		log:                  log,
		metricReconcilerTime: recTime,
		metricReconcileTeam:  teamTime,
		syncQueue:            queue,
		syncQueueChan:        channel,
	}
}

func (m *Manager) Close() {
	m.syncQueue.Close()
}

func (m *Manager) SyncTeams(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case input := <-m.syncQueueChan:
			log := m.log.WithField("team", input.Team.Slug)

			if !m.setTeamInFlight(input.Team.Slug) {
				log.Info("already in flight - adding to back of queue")
				time.Sleep(100 * time.Millisecond)
				if err := m.syncQueue.Add(input); err != nil {
					log.WithError(err).Error("failed while re-queueing team that is in flight")
				}
				continue
			}

			ctx, cancel := context.WithTimeout(ctx, reconcilerTimeout)
			if err := m.reconcileTeam(ctx, input); err != nil {
				log.WithError(err).Error("reconcile team")
			}

			cancel()
			m.unsetTeamInFlight(input.Team.Slug)
		}
	}
}

func (m *Manager) Register(r Reconciler) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.reconcilers = append(m.reconcilers, r)
}

func (m *Manager) ScheduleAllTeams(ctx context.Context, fullSyncInterval time.Duration) error {
	for {
		if err := m.scheduleAllTeams(ctx); err != nil {
			m.log.WithError(err).Errorf("error in run()")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(fullSyncInterval):
		}
	}
}

func (m *Manager) SyncWithAPI(ctx context.Context) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	r := &protoapi.RegisterReconcilerRequest{}
	for _, rec := range m.reconcilers {
		r.Reconcilers = append(r.Reconcilers, rec.Configuration())
	}

	_, err := m.apiclient.Reconcilers().Register(ctx, r)
	return err
}

func (m *Manager) setTeamInFlight(teamSlug string) bool {
	m.teamsInFlightLock.Lock()
	defer m.teamsInFlightLock.Unlock()

	if _, inFlight := m.teamsInFlight[teamSlug]; !inFlight {
		m.teamsInFlight[teamSlug] = struct{}{}
		return true
	}
	return false
}

func (m *Manager) unsetTeamInFlight(teamSlug string) {
	m.teamsInFlightLock.Lock()
	defer m.teamsInFlightLock.Unlock()

	delete(m.teamsInFlight, teamSlug)
}

func (m *Manager) enabledReconcilers(ctx context.Context) ([]Reconciler, error) {
	reconcilers, err := getReconcilers(ctx, m.apiclient.Reconcilers())
	if err != nil {
		return nil, err
	}

	ret := make([]Reconciler, 0)
	for _, r := range m.reconcilers {
		for _, er := range reconcilers {
			if r.Name() == er.Name && er.Enabled {
				ret = append(ret, r)
			}
		}
	}
	return ret, nil
}

func (m *Manager) reconcileTeam(ctx context.Context, input Input) error {
	reconcilers, err := m.enabledReconcilers(ctx)
	if err != nil {
		return err
	}

	teamStart := time.Now()
	log := m.log.WithField("team", input.Team.Slug)
	if input.CorrelationID != "" {
		log = log.WithField("correlation_id", input.CorrelationID)
		ctx = context.WithValue(ctx, ctxCorrelationID, input.CorrelationID)
	}

	if input.TraceID != "" {
		log = log.WithField("trace_id", input.TraceID)
	}

	for _, r := range reconcilers {
		log := log.WithField("reconciler", r.Name())
		start := time.Now()
		hasError := false
		if err := r.Reconcile(ctx, m.apiclient, input.Team, log); err != nil {
			hasError = true
			log.WithError(err).Errorf("error during team reconciler")
		}

		// TODO: register reconciler errors for team via GRPC
		// TODO: set last successful timestamp for team sync

		m.metricReconcilerTime.Record(
			ctx,
			time.Since(start).Milliseconds(),
			metric.WithAttributes(
				attribute.String("reconciler", r.Name()),
				attribute.Bool("error", hasError),
			),
		)
	}

	m.metricReconcileTeam.Record(ctx, time.Since(teamStart).Milliseconds())
	return nil
}

func (m *Manager) scheduleAllTeams(ctx context.Context) error {
	reconcilers, err := m.enabledReconcilers(ctx)
	if err != nil {
		return err
	}

	if len(reconcilers) == 0 {
		m.log.Info("no reconcilers enabled")
		return nil
	}

	correlationID := uuid.New()
	it := iterator.New(ctx, 20, func(limit, offset int64) (*protoapi.ListTeamsResponse, error) {
		return m.apiclient.Teams().List(ctx, &protoapi.ListTeamsRequest{Limit: limit, Offset: offset})
	})

	for it.Next() {
		team := it.Value()
		err := m.syncQueue.Add(Input{
			CorrelationID: correlationID.String(),
			Team:          team,
		})
		if err != nil {
			m.log.WithField("team", team.Slug).WithError(err).Errorf("error while adding team to queue")
		}
	}

	return it.Err()
}

func getReconcilers(ctx context.Context, client protoapi.ReconcilersClient) ([]*protoapi.Reconciler, error) {
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListReconcilersResponse, error) {
		return client.List(ctx, &protoapi.ListReconcilersRequest{Limit: limit, Offset: offset})
	})

	reconcilers := make([]*protoapi.Reconciler, 0)
	for it.Next() {
		reconcilers = append(reconcilers, it.Value())
	}
	return reconcilers, it.Err()
}

func GetTeamMembers(ctx context.Context, client protoapi.TeamsClient, teamSlug string) ([]*protoapi.TeamMember, error) {
	members := make([]*protoapi.TeamMember, 0)
	limit, offset := int64(100), int64(0)
	for {
		resp, err := client.Members(ctx, &protoapi.ListTeamMembersRequest{
			Limit:  limit,
			Offset: offset,
			Slug:   teamSlug,
		})
		if err != nil {
			return nil, err
		}

		members = append(members, resp.Nodes...)

		if !resp.PageInfo.HasNextPage {
			break
		}

		offset += limit
	}
	return members, nil
}
