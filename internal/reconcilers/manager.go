package reconcilers

import (
	"context"
	"sync"
	"time"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
)

const (
	ManagedByLabelName  = "managed-by"
	ManagedByLabelValue = "teams-backend"

	// TeamNamePrefix Prefix that can be used for team-like objects in external systems
	TeamNamePrefix              = "nais-team-"
	CnrmServiceAccountAccountID = "nais-sa-cnrm"
)

const (
	reconcilerWorkers    = 10
	fullTeamSyncInterval = time.Minute * 30
)

type Manager struct {
	apiclient   *apiclient.APIClient
	lock        sync.Mutex
	reconcilers []Reconciler
	log         logrus.FieldLogger
}

func (m *Manager) Register(r Reconciler) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.reconcilers = append(m.reconcilers, r)
}

func NewManager(c *apiclient.APIClient, log logrus.FieldLogger) *Manager {
	return &Manager{
		apiclient: c,
		log:       log,
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

func (m *Manager) run() error {
	m.log.Infof("start full team sync")

	/*
		correlationID := uuid.New()

		teams, err := teamSync.ScheduleAllTeams(ctx, correlationID)
		if err != nil {
			log.WithError(err).Errorf("full team sync")
			fullTeamSyncTimer.Reset(time.Second * 1)
			break
		}

	*/

	return nil
}

func (m *Manager) Run(ctx context.Context, fullSyncInterval time.Duration) error {
	for {
		if err := m.run(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(fullSyncInterval):
		}
	}
}

// Reconciler Interface for all reconcilers
type Reconciler interface {
	Configuration() *protoapi.NewReconciler
	Name() string
	Reconfigure(ctx context.Context, client *apiclient.APIClient, log logrus.FieldLogger) error
	Reconcile(ctx context.Context, client *apiclient.APIClient, teamSlug string, log logrus.FieldLogger) error
	Delete(ctx context.Context, client *apiclient.APIClient, teamSlug string, log logrus.FieldLogger) error
}
