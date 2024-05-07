package grafana_reconciler

import (
	"context"

	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"

	grafana_accesscontrol "github.com/grafana/grafana-openapi-client-go/client/access_control"
	grafana_serviceaccounts "github.com/grafana/grafana-openapi-client-go/client/service_accounts"
	grafana_teams "github.com/grafana/grafana-openapi-client-go/client/teams"
	grafana_users "github.com/grafana/grafana-openapi-client-go/client/users"
)

const (
	grafanaReconcilerName = "grafana"
)

type grafanaReconciler struct {
	users           grafana_users.ClientService
	teams           grafana_teams.ClientService
	rbac            grafana_accesscontrol.ClientService
	serviceAccounts grafana_serviceaccounts.ClientService
}

func New(
	users grafana_users.ClientService,
	teams grafana_teams.ClientService,
	rbac grafana_accesscontrol.ClientService,
	serviceAccounts grafana_serviceaccounts.ClientService,
) (*grafanaReconciler, error) {
	return &grafanaReconciler{
		users:           users,
		teams:           teams,
		rbac:            rbac,
		serviceAccounts: serviceAccounts,
	}, nil
}

func (r *grafanaReconciler) Name() string {
	return grafanaReconcilerName
}

func (r *grafanaReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "Grafana",
		Description: "Create and reconsilate Grafana service accounts and permissions for teams.",
		MemberAware: true,
	}
}

func (r *grafanaReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	return nil
}

func (r *grafanaReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	return nil
}
