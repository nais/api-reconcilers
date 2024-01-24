package reconcilers

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
)

const (
	ManagedByLabelName          = "managed-by"
	ManagedByLabelValue         = "teams-backend"
	CnrmServiceAccountAccountID = "nais-sa-cnrm"
)

type Manager struct {
	apiclient   *apiclient.APIClient
	lock        sync.Mutex
	reconcilers []Reconciler
	log         logrus.FieldLogger
}

func NewManager(c *apiclient.APIClient, log logrus.FieldLogger) *Manager {
	return &Manager{
		apiclient: c,
		log:       log,
	}
}

func (m *Manager) Register(r Reconciler) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.reconcilers = append(m.reconcilers, r)
}

func (m *Manager) Run(ctx context.Context, fullSyncInterval time.Duration) error {
	if err := m.syncWithAPI(ctx); err != nil {
		return err
	}

	for {
		if err := m.run(ctx); err != nil {
			m.log.WithError(err).Errorf("error in run()")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(fullSyncInterval):
		}
	}
}

func (m *Manager) syncWithAPI(ctx context.Context) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	r := &protoapi.RegisterReconcilerRequest{}
	for _, rec := range m.reconcilers {
		r.Reconcilers = append(r.Reconcilers, rec.Configuration())
	}

	_, err := m.apiclient.Reconcilers().Register(ctx, r)
	return err
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

func (m *Manager) run(ctx context.Context) error {
	reconcilers, err := m.enabledReconcilers(ctx)
	if err != nil {
		return err
	}

	if len(reconcilers) == 0 {
		m.log.Info("no reconcilers enabled")
		return nil
	}

	teams, err := getTeams(ctx, m.apiclient.Teams())
	if err != nil {
		return err
	}

	correlationID := uuid.New()
	log := m.log.WithField("correlation_id", correlationID)

	for _, team := range teams {
		log := log.WithField("team", team.Slug)
		for _, r := range reconcilers {
			log := log.WithField("reconciler", r.Name())
			if err := r.Reconcile(ctx, m.apiclient, team, log); err != nil {
				log.WithError(err).Errorf("error during team reconciler")
			}
		}
	}

	return nil
}

func getTeams(ctx context.Context, client protoapi.TeamsClient) ([]*protoapi.Team, error) {
	teams := make([]*protoapi.Team, 0)
	limit, offset := int64(100), int64(0)
	for {
		resp, err := client.List(ctx, &protoapi.ListTeamsRequest{
			Limit:  limit,
			Offset: offset,
		})
		if err != nil {
			return nil, err
		}

		teams = append(teams, resp.Nodes...)

		if !resp.PageInfo.HasNextPage {
			break
		}

		offset += limit
	}

	return teams, nil
}

func getReconcilers(ctx context.Context, client protoapi.ReconcilersClient) ([]*protoapi.Reconciler, error) {
	reconcilers := make([]*protoapi.Reconciler, 0)
	limit, offset := int64(100), int64(0)
	for {
		resp, err := client.List(ctx, &protoapi.ListReconcilersRequest{
			Limit:  limit,
			Offset: offset,
		})
		if err != nil {
			return nil, err
		}

		reconcilers = append(reconcilers, resp.Nodes...)

		if !resp.PageInfo.HasNextPage {
			break
		}

		offset += limit
	}
	return reconcilers, nil
}
