package grafana_reconciler

import (
	"context"
	"strings"
	"testing"

	grafanateams "github.com/grafana/grafana-openapi-client-go/client/teams"
	"github.com/grafana/grafana-openapi-client-go/models"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

func TestTeamWithoutID(t *testing.T) {
	for _, operation := range []string{"reconcile", "delete"} {
		t.Run(operation, func(t *testing.T) {
			name := "nais"
			teams := NewMockTeamsClientService(t)
			teams.EXPECT().SearchTeams(mock.Anything).Return(&grafanateams.SearchTeamsOK{
				Payload: &models.SearchTeamQueryResult{Teams: []*models.TeamDTO{{Name: &name}}},
			}, nil).Once()
			r := &grafanaReconciler{teams: teams}
			var err error
			if operation == "reconcile" {
				_, err = r.getOrCreateTeam(context.Background(), name)
			} else {
				r.folders = NewMockFoldersClientService(t)
				r.provisioning = NewMockProvisioningClientService(t)
				err = r.Delete(context.Background(), nil, &protoapi.Team{Slug: name}, logrus.New())
			}
			if err == nil || !strings.Contains(err.Error(), "has no ID") {
				t.Fatalf("expected missing team ID error, got %v", err)
			}
		})
	}
}
