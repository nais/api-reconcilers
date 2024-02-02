package reconcilers

import (
	"context"
	"errors"
	"slices"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/golang/protobuf/proto"
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
	reconcilers []Reconciler
	// Reconcilers to enable during registration
	reconcilersToEnable []string
	log                 logrus.FieldLogger
	pubsubSubscription  *pubsub.Subscription
	syncQueueChan       <-chan Input
	syncQueue           Queue
	inFlight            InFlight

	metricReconcilerTime metric.Int64Histogram
	metricReconcileTeam  metric.Int64Histogram
}

// NewManager creates a new Manager instance
func NewManager(ctx context.Context, c *apiclient.APIClient, enableDuringRegistration []string, pubsubSubscriptionID string, log logrus.FieldLogger) *Manager {
	meter := otel.Meter("reconcilers")
	recTime, err := meter.Int64Histogram("reconciler_duration", metric.WithDescription("Duration of a specific reconciler, regardless of team, in milliseconds"))
	if err != nil {
		log.WithError(err).Errorf("error when creating metric")
	}
	teamTime, err := meter.Int64Histogram("reconcile_team_duration", metric.WithDescription("Duration when reconciling an entire team, in milliseconds"))
	if err != nil {
		log.WithError(err).Errorf("error when creating metric")
	}

	var pubsubSubscription *pubsub.Subscription
	pubsubClient, err := pubsub.NewClient(ctx, pubsub.DetectProjectID)
	if err != nil {
		log.WithError(err).Errorf("error when creating pubsub client")
	} else {
		pubsubSubscription = pubsubClient.Subscription(pubsubSubscriptionID)
	}

	queue, channel := NewQueue()
	return &Manager{
		apiclient:            c,
		log:                  log,
		metricReconcilerTime: recTime,
		metricReconcileTeam:  teamTime,
		syncQueue:            queue,
		syncQueueChan:        channel,
		inFlight:             NewInFlight(),
		reconcilersToEnable:  enableDuringRegistration,
		pubsubSubscription:   pubsubSubscription,
	}
}

// AddReconciler will add a reconciler to the manager.
func (m *Manager) AddReconciler(r Reconciler) {
	m.reconcilers = append(m.reconcilers, r)
}

// RegisterReconcilersWithAPI will register all reconcilers with the NAIS API.
func (m *Manager) RegisterReconcilersWithAPI(ctx context.Context) error {
	r := &protoapi.RegisterReconcilerRequest{}
	for _, rec := range m.reconcilers {
		body := rec.Configuration()
		body.EnableByDefault = slices.Contains(m.reconcilersToEnable, rec.Name())
		r.Reconcilers = append(r.Reconcilers, body)
	}

	_, err := m.apiclient.Reconcilers().Register(ctx, r)
	return err
}

// ListenForEvents will listen for events on the pubsub subscription, if configured. This function will block until the
// context is canceled.
func (m *Manager) ListenForEvents(ctx context.Context) error {
	if m.pubsubSubscription == nil {
		return nil
	}

	for {
		err := m.pubsubSubscription.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
			defer msg.Ack()

			correlationID := uuid.New()

			if id := msg.Attributes["CorrelationID"]; id != "" {
				if i, err := uuid.Parse(id); err != nil {
					m.log.WithError(err).Error("error while parsing correlation ID from the event")
				} else {
					correlationID = i
				}
			}

			// TODO: handle traceID from message attributes

			event := protoapi.EventTypes(protoapi.EventTypes_value[msg.Attributes["EventType"]])

			switch event {
			case protoapi.EventTypes_EVENT_TEAM_DELETED,
				protoapi.EventTypes_EVENT_TEAM_UPDATED:
				input := Input{
					CorrelationID: correlationID.String(),
				}

				var obj interface {
					proto.Message
					GetSlug() string
				}
				if event == protoapi.EventTypes_EVENT_TEAM_DELETED {
					obj = &protoapi.EventTeamDeleted{}
					input.Delete = true
				} else {
					obj = &protoapi.EventTeamUpdated{}
				}

				if err := proto.Unmarshal(msg.Data, obj); err != nil {
					m.log.WithError(err).Error("error while unmarshalling event")
					return
				}

				input.TeamSlug = obj.GetSlug()
				err := m.syncQueue.Add(input)

				if err != nil {
					msg.Nack()
					m.log.WithError(err).Error("error while adding team to queue")
					return
				}

			case protoapi.EventTypes_EVENT_RECONCILER_DISABLED:
				// no need to handle this for now
			case protoapi.EventTypes_EVENT_RECONCILER_ENABLED,
				protoapi.EventTypes_EVENT_RECONCILER_CONFIGURED,
				protoapi.EventTypes_EVENT_SYNC_ALL_TEAMS:
				if err := m.scheduleAllTeams(ctx, correlationID); err != nil {
					m.log.WithError(err).Error("error while scheduling all teams")
				}

			default:
				m.log.WithField("event_type", event).Error("unknown event type")
			}
		})

		if errors.Is(err, context.Canceled) {
			return nil
		} else if err != nil {
			m.log.WithError(err).Error("error while receiving pubsub message")
		}

		time.Sleep(10 * time.Second)
	}
}

// Run will pull an entry from the queue and start a reconcile process. This function will block until the context is
// canceled.
func (m *Manager) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case input := <-m.syncQueueChan:
			m.syncTeam(ctx, input)
		}
	}
}

// SyncAllTeams will schedule all teams for reconciliation at a regular interval. This function will block until the
// context is canceled.
func (m *Manager) SyncAllTeams(ctx context.Context, fullSyncInterval time.Duration) error {
	for {
		if err := m.scheduleAllTeams(ctx, uuid.New()); err != nil {
			m.log.WithError(err).Errorf("error when scheduling all teams")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(fullSyncInterval):
		}
	}
}

// Close will close the manager and all its resources.
func (m *Manager) Close() {
	m.syncQueue.Close()
}

// syncTeam will mark the team as "in flight" and start the reconciliation process. If the team is already in flight, it
// will be added to the back of the queue. Based on the input, the team will either be deleted or reconciled.
func (m *Manager) syncTeam(ctx context.Context, input Input) {
	log := m.log.WithField("team", input.TeamSlug)

	if !m.inFlight.Set(input.TeamSlug) {
		log.Info("already in flight - adding to back of queue")
		time.Sleep(100 * time.Millisecond)
		if err := m.syncQueue.Add(input); err != nil {
			log.WithError(err).Error("failed while re-queueing team that is in flight")
		}
		return
	}

	defer m.inFlight.Remove(input.TeamSlug)

	resp, err := m.apiclient.Teams().Get(ctx, &protoapi.GetTeamRequest{Slug: input.TeamSlug})
	if err != nil {
		log.WithError(err).Error("error while getting team")
		if err := m.syncQueue.Add(input); err != nil {
			log.WithError(err).Error("failed while re-queueing team that is in flight")
		}

		return
	}

	team := resp.Team

	ctx, cancel := context.WithTimeout(ctx, reconcilerTimeout)
	defer cancel()

	reconcilers, err := m.enabledReconcilers(ctx)
	if err != nil {
		log.WithError(err).Error("unable to fetch reconcilers")
		return
	}

	if input.Delete {
		if err := m.deleteTeam(ctx, reconcilers, team, input); err != nil {
			log.WithError(err).Error("delete team")
		}
	} else {
		if err := m.reconcileTeam(ctx, reconcilers, team, input); err != nil {
			log.WithError(err).Error("reconcile team")
		}
	}
}

// enabledReconcilers will fetch all reconcilers from the NAIS API, and return the ones we have registered locally in a
// specific order.
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

// deleteTeam will pass the team through to all enabled reconcilers, effectively deleting the team from all configured
// external systems.
func (m *Manager) deleteTeam(ctx context.Context, reconcilers []Reconciler, naisTeam *protoapi.Team, input Input) error {
	teamStart := time.Now()
	log := m.log.WithField("team", input.TeamSlug)

	if input.CorrelationID != "" {
		log = log.WithField("correlation_id", input.CorrelationID)
		ctx = context.WithValue(ctx, ctxCorrelationID, input.CorrelationID)
	}

	if input.TraceID != "" {
		log = log.WithField("trace_id", input.TraceID)
	}

	successfulDelete := true
	for _, r := range reconcilers {
		log := log.WithField("reconciler", r.Name())
		start := time.Now()
		hasError := false

		if err := r.Delete(ctx, m.apiclient, naisTeam, log); err != nil {
			successfulDelete = false
			hasError = true

			log.WithError(err).Errorf("error during team deletion")

			req := &protoapi.SetReconcilerErrorForTeamRequest{
				CorrelationId:  input.CorrelationID,
				ReconcilerName: r.Name(),
				ErrorMessage:   err.Error(),
				TeamSlug:       input.TeamSlug,
			}
			if _, err := m.apiclient.Reconcilers().SetReconcilerErrorForTeam(ctx, req); err != nil {
				log.WithError(err).Errorf("error while adding deletion error")
			}
		} else {
			req := &protoapi.RemoveReconcilerErrorForTeamRequest{
				ReconcilerName: r.Name(),
				TeamSlug:       input.TeamSlug,
			}
			if _, err := m.apiclient.Reconcilers().RemoveReconcilerErrorForTeam(ctx, req); err != nil {
				log.WithError(err).Errorf("error while removing deletion error")
			}
		}

		m.metricReconcilerTime.Record(
			ctx,
			time.Since(start).Milliseconds(),
			metric.WithAttributes(
				attribute.String("reconciler", r.Name()),
				attribute.Bool("error", hasError),
				attribute.Bool("delete", true),
			),
		)
	}

	if successfulDelete {
		req := &protoapi.DeleteTeamRequest{
			Slug: input.TeamSlug,
		}
		if _, err := m.apiclient.Teams().Delete(ctx, req); err != nil {
			log.WithError(err).Errorf("error while deleting team")
		}
	}

	m.metricReconcileTeam.Record(
		ctx,
		time.Since(teamStart).Milliseconds(),
		metric.WithAttributes(
			attribute.Bool("delete", true),
		),
	)
	return nil
}

// reconcileTeam will pass the team through to all enabled reconcilers, effectively synchronizing the team to all
// configured external systems.
func (m *Manager) reconcileTeam(ctx context.Context, reconcilers []Reconciler, naisTeam *protoapi.Team, input Input) error {
	teamStart := time.Now()
	log := m.log.WithField("team", input.TeamSlug)

	if input.CorrelationID != "" {
		log = log.WithField("correlation_id", input.CorrelationID)
		ctx = context.WithValue(ctx, ctxCorrelationID, input.CorrelationID)
	}

	if input.TraceID != "" {
		log = log.WithField("trace_id", input.TraceID)
	}

	successfulSync := true
	for _, r := range reconcilers {
		log := log.WithField("reconciler", r.Name())
		start := time.Now()
		hasError := false

		if err := r.Reconcile(ctx, m.apiclient, naisTeam, log); err != nil {
			successfulSync = false
			hasError = true

			log.WithError(err).Errorf("error during team reconciler")

			req := &protoapi.SetReconcilerErrorForTeamRequest{
				CorrelationId:  input.CorrelationID,
				ReconcilerName: r.Name(),
				ErrorMessage:   err.Error(),
				TeamSlug:       input.TeamSlug,
			}
			if _, err := m.apiclient.Reconcilers().SetReconcilerErrorForTeam(ctx, req); err != nil {
				log.WithError(err).Errorf("error while adding reconciler error")
			}
		} else {
			req := &protoapi.RemoveReconcilerErrorForTeamRequest{
				ReconcilerName: r.Name(),
				TeamSlug:       input.TeamSlug,
			}
			if _, err := m.apiclient.Reconcilers().RemoveReconcilerErrorForTeam(ctx, req); err != nil {
				log.WithError(err).Errorf("error while removing reconciler error")
			}
		}

		m.metricReconcilerTime.Record(
			ctx,
			time.Since(start).Milliseconds(),
			metric.WithAttributes(
				attribute.String("reconciler", r.Name()),
				attribute.Bool("error", hasError),
			),
		)
	}

	if successfulSync {
		req := &protoapi.SuccessfulTeamSyncRequest{
			TeamSlug: input.TeamSlug,
		}
		if _, err := m.apiclient.Reconcilers().SuccessfulTeamSync(ctx, req); err != nil {
			log.WithError(err).Errorf("error while setting successful sync for team")
		}
	}

	m.metricReconcileTeam.Record(ctx, time.Since(teamStart).Milliseconds())
	return nil
}

// scheduleAllTeams will fetch all teams from the NAIS API and put them on the reconciler queue
func (m *Manager) scheduleAllTeams(ctx context.Context, correlationID uuid.UUID) error {
	reconcilers, err := m.enabledReconcilers(ctx)
	if err != nil {
		return err
	} else if len(reconcilers) == 0 {
		m.log.Info("no reconcilers enabled")
		return nil
	}

	teams, err := getTeams(ctx, m.apiclient.Teams())
	if err != nil {
		return err
	}

	for _, team := range teams {
		err := m.syncQueue.Add(Input{
			CorrelationID: correlationID.String(),
			TeamSlug:      team.Slug,
		})
		if err != nil {
			m.log.WithField("team", team.Slug).WithError(err).Errorf("error while adding team to queue")
		}
	}

	return nil
}

// getTeams retrieves all teams from the NAIS API
func getTeams(ctx context.Context, client protoapi.TeamsClient) ([]*protoapi.Team, error) {
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamsResponse, error) {
		return client.List(ctx, &protoapi.ListTeamsRequest{Limit: limit, Offset: offset})
	})

	teams := make([]*protoapi.Team, 0)
	for it.Next() {
		teams = append(teams, it.Value())
	}
	return teams, it.Err()
}

// getReconcilers retrieves all reconcilers from the NAIS API
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

// GetTeamMembers retrieves all members of a team from the NAIS API
func GetTeamMembers(ctx context.Context, client protoapi.TeamsClient, teamSlug string) ([]*protoapi.TeamMember, error) {
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamMembersResponse, error) {
		return client.Members(ctx, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: limit, Offset: offset})
	})

	members := make([]*protoapi.TeamMember, 0)
	for it.Next() {
		members = append(members, it.Value())
	}
	return members, it.Err()
}
