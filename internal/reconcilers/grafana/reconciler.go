package grafana_reconciler

import (
	"context"
	"net/http"
	"strings"

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
	grafanaTeam, err := r.getOrCreateTeam(ctx, naisTeam)
	if err != nil {
		return err
	}

	if err := r.reconcileTeamMembers(ctx, naisTeam, grafanaTeam); err != nil {
		return err
	}

	return nil
}

func (r *grafanaReconciler) getOrCreateTeam(ctx context.Context, naisTeam *protoapi.Team) (*protoapi.Team, error) {
	payload := `{"name":"` + generateTeamName(naisTeam.Name) + `"}`
	endpoint := r.endpoint + "/api/teams"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+r.serviceAccountToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (r *grafanaReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	// TODO: Implement Grafana delete
	endpoint := r.endpoint + "/teams/" + generateTeamName(naisTeam.Name)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+r.serviceAccountToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// TODO: Check if status code is 200
	if resp.StatusCode != http.StatusOK {
		return err
	}

	return nil
}

func generateTeamName(teamName string) string {
	return "team-" + teamName
}
