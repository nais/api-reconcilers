package reconcilers

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"github.com/google/uuid"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/iterator"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type ctxKey int

const (
	reconcilerTimeout        = time.Minute * 15
	ctxCorrelationID  ctxKey = iota
)

type Manager struct {
	apiclient   *apiclient.APIClient
	reconcilers []Reconciler
	// Reconcilers to enable during registration
	reconcilersToEnable []string
	log                 logrus.FieldLogger
	pubsubSubscription  *pubsub.Subscriber
	syncQueue           Queue

	metricReconcilerTime metric.Int64Histogram
	metricReconcileTeam  metric.Int64Histogram
}

// NewManager creates a new Manager instance
func NewManager(ctx context.Context, c *apiclient.APIClient, enableDuringRegistration []string, pubsubSubscriptionID, pubsubProjectID string, log logrus.FieldLogger) *Manager {
	start := time.Now()
	meter := otel.Meter("reconcilers")
	recTime, err := meter.Int64Histogram("reconciler_duration", metric.WithDescription("Duration of a specific reconciler, regardless of team, in milliseconds"))
	if err != nil {
		log.WithError(err).Errorf("error when creating metric")
	}
	teamTime, err := meter.Int64Histogram("reconcile_team_duration", metric.WithDescription("Duration when reconciling an entire team, in milliseconds"))
	if err != nil {
		log.WithError(err).Errorf("error when creating metric")
	}

	log.WithField("duration", time.Since(start).String()).Debug("metrics created")

	var pubsubSubscription *pubsub.Subscriber
	pubsubClient, err := pubsub.NewClient(ctx, pubsubProjectID)
	log.WithField("duration", time.Since(start).String()).Debug("pubsub client created")
	if err != nil {
		log.WithError(err).Errorf("error when creating pubsub client")
	} else {
		pubsubSubscription = pubsubClient.Subscriber(pubsubSubscriptionID)
		log.WithField("duration", time.Since(start).String()).Debug("subscription created")
	}

	return &Manager{
		apiclient:            c,
		log:                  log,
		metricReconcilerTime: recTime,
		metricReconcileTeam:  teamTime,
		syncQueue:            NewQueue(),
		reconcilersToEnable:  enableDuringRegistration,
		pubsubSubscription:   pubsubSubscription,
	}
}

// AddReconciler will add a reconciler to the manager.
func (m *Manager) AddReconciler(r Reconciler) {
	m.log.WithField("reconciler", r.Name()).Debugf("adding reconciler to the manager")
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
func (m *Manager) ListenForEvents(ctx context.Context) {
	if m.pubsubSubscription == nil {
		m.log.Warn("no pubsub subscription configured, not listening for events")
		return
	}

	for {
		err := m.pubsubSubscription.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
			defer msg.Ack()
			m.log.WithField("type", msg.Attributes["EventType"]).Debug("received pubsub message")

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
				protoapi.EventTypes_EVENT_TEAM_UPDATED,
				protoapi.EventTypes_EVENT_TEAM_CREATED:

				var obj interface {
					proto.Message
					GetSlug() string
				}

				input := ReconcileRequest{
					CorrelationID: correlationID.String(),
				}

				if event == protoapi.EventTypes_EVENT_TEAM_DELETED {
					obj = &protoapi.EventTeamDeleted{}
				} else if event == protoapi.EventTypes_EVENT_TEAM_CREATED {
					obj = &protoapi.EventTeamCreated{}
				} else {
					obj = &protoapi.EventTeamUpdated{}
				}

				if err := proto.Unmarshal(msg.Data, obj); err != nil {
					m.log.WithError(err).Error("error while unmarshalling event")
					return
				}

				input.TeamSlug = obj.GetSlug()
				if err := m.syncQueue.Add(input); err != nil {
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

		if err == nil || errors.Is(err, context.Canceled) {
			// Receive will return nil error when canceled
			return
		} else {
			m.log.WithError(err).Error("error while receiving pubsub message")
		}

		time.Sleep(10 * time.Second)
	}
}

// Run will pull an entry from the queue and start a reconcile process. This function will block until the context is
// canceled.
func (m *Manager) Run(ctx context.Context) {
	stop := context.AfterFunc(ctx, m.syncQueue.Close)
	defer stop()
	for ctx.Err() == nil {
		input, shutdown := m.syncQueue.Get()
		if shutdown {
			return
		}
		if ctx.Err() != nil {
			m.syncQueue.Done(input)
			return
		}
		if m.syncTeam(ctx, input) {
			m.syncQueue.Forget(input)
		} else if ctx.Err() == nil {
			delay, err := m.syncQueue.Retry(input)
			if err != nil {
				m.log.WithError(err).WithField("team", input.TeamSlug).Error("failed while scheduling team retry")
			} else {
				m.log.WithField("team", input.TeamSlug).WithField("delay", delay).Info("scheduled team retry")
			}
		}
		m.syncQueue.Done(input)
	}
}

// SyncAllTeams will schedule all teams for reconciliation at a regular interval. This function will block until the
// context is canceled.
func (m *Manager) SyncAllTeams(ctx context.Context, fullSyncInterval time.Duration) error {
	for {
		m.log.Debugf("scheduling all teams for reconciliation")
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

// syncTeam returns whether reconciliation or deletion completed without needing a retry.
func (m *Manager) syncTeam(ctx context.Context, req ReconcileRequest) bool {
	log := m.log.WithField("team", req.TeamSlug)

	resp, err := m.apiclient.Teams().Get(ctx, &protoapi.GetTeamRequest{Slug: req.TeamSlug})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Info("team not found, team will not be requeued")
			return true
		}

		log.WithError(err).Error("error while getting team, retrying later")
		return false
	}

	ctx, cancel := context.WithTimeout(ctx, reconcilerTimeout)
	defer cancel()

	reconcilers, err := m.enabledReconcilers(ctx)
	if err != nil {
		log.WithError(err).Error("unable to fetch reconcilers")
		return false
	}

	return m.runTeamReconcilers(ctx, reconcilers, resp.Team, req)
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

func (m *Manager) runTeamReconcilers(ctx context.Context, reconcilers []Reconciler, naisTeam *protoapi.Team, input ReconcileRequest) bool {
	teamStart := time.Now()
	log := m.log.WithField("team", input.TeamSlug)

	if input.CorrelationID != "" {
		log = log.WithField("correlation_id", input.CorrelationID)
		ctx = context.WithValue(ctx, ctxCorrelationID, input.CorrelationID)
	}

	if input.TraceID != "" {
		log = log.WithField("trace_id", input.TraceID)
	}

	action, process := "reconcile", "reconciliation"
	var teamAttributes []attribute.KeyValue
	deleting := naisTeam.DeleteKeyConfirmedAt != nil
	if deleting {
		action, process = "delete", "deletion"
		reconcilers = slices.Clone(reconcilers)
		slices.Reverse(reconcilers)
		teamAttributes = append(teamAttributes, attribute.Bool("delete", true))
	}

	reconcilerNames := make([]string, len(reconcilers))
	for i, r := range reconcilers {
		reconcilerNames[i] = r.Name()
	}
	log.
		WithField("time", teamStart).
		WithField("reconcilers", reconcilerNames).
		Debugf("start team %s process", process)

	success := true
	for _, r := range reconcilers {
		log := log.WithField("reconciler", r.Name())
		start := time.Now()
		operation := r.Reconcile
		if deleting {
			operation = r.Delete
		}

		log.WithField("time", start).Debugf("start %s", action)
		err := operation(ctx, m.apiclient, naisTeam, log)
		if err != nil {
			success = false
			log.WithError(err).Errorf("error during team %s", process)

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
				success = false
				log.WithError(err).Errorf("error while removing reconciler error")
			}
		}

		log.
			WithField("duration", time.Since(start)).
			WithField("has_error", err != nil).
			Debugf("finished %s", action)

		attributes := append([]attribute.KeyValue{
			attribute.String("reconciler", r.Name()),
			attribute.Bool("error", err != nil),
		}, teamAttributes...)
		m.metricReconcilerTime.Record(
			ctx,
			time.Since(start).Milliseconds(),
			metric.WithAttributes(attributes...),
		)
	}

	if success && deleting {
		if _, err := m.apiclient.Teams().Delete(ctx, &protoapi.DeleteTeamRequest{Slug: input.TeamSlug}); err != nil {
			success = false
			log.WithError(err).Error("error while deleting team")
		}
	} else if success {
		req := &protoapi.SuccessfulTeamSyncRequest{
			TeamSlug: input.TeamSlug,
		}
		if _, err := m.apiclient.Reconcilers().SuccessfulTeamSync(ctx, req); err != nil {
			success = false
			log.WithError(err).Errorf("error while setting successful sync for team")
		}
	}

	log.
		WithField("duration", time.Since(teamStart)).
		WithField("success", success).
		Debugf("finished team %s process", process)

	m.metricReconcileTeam.Record(ctx, time.Since(teamStart).Milliseconds(), metric.WithAttributes(teamAttributes...))
	return success
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

	if err := m.scheduleTeams(ctx, correlationID); err != nil {
		m.log.WithError(err).Error("error while scheduling teams for reconciliation")
	}

	return nil
}

func (m *Manager) scheduleTeams(ctx context.Context, correlationID uuid.UUID) error {
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamsResponse, error) {
		return m.apiclient.Teams().List(ctx, &protoapi.ListTeamsRequest{Limit: limit, Offset: offset})
	})

	num := 0
	for it.Next() {
		err := m.syncQueue.Add(ReconcileRequest{
			CorrelationID: correlationID.String(),
			TeamSlug:      it.Value().Slug,
		})
		if err != nil {
			return fmt.Errorf("error while adding team to queue: %w", err)
		}
		num++
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("error while fetching active teams for reconciliation: %w", err)
	}

	m.log.WithField("num_teams", num).Debugf("added teams to reconcile queue")
	return nil
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
