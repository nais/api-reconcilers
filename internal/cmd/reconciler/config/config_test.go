package config_test

import (
	"context"
	"slices"
	"testing"

	"github.com/nais/api-reconcilers/internal/cmd/reconciler/config"

	"github.com/sethvargo/go-envconfig"
)

func TestNew(t *testing.T) {
	ctx := context.Background()
	lookuper := envconfig.MapLookuper(map[string]string{
		"GCP_CLUSTERS":                      `{"name":{"project_id":"some-id","teams_folder_id":"123456789"}}`,
		"FEATURE_GRAFANA_ALERT_PILOT_TEAMS": "team-a,team-b",
	})
	cfg, err := config.NewConfig(ctx, lookuper)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	clusterName := "name"
	cluster, exists := cfg.GCP.Clusters[clusterName]
	if !exists {
		t.Fatalf("expected cluster %q to exist", clusterName)
	}

	if expected := "some-id"; cluster.ProjectID != expected {
		t.Errorf("expected project ID %q, got %q", expected, cluster.ProjectID)
	}

	if expected := int64(123456789); cluster.TeamsFolderID != expected {
		t.Errorf("expected teams folder ID %d, got %d", expected, cluster.TeamsFolderID)
	}

	if expected := []string{"team-a", "team-b"}; !slices.Equal(cfg.FeatureFlags.GrafanaAlertPilotTeams, expected) {
		t.Errorf("expected Grafana alert pilot teams %v, got %v", expected, cfg.FeatureFlags.GrafanaAlertPilotTeams)
	}
}

func TestGrafanaAlertPilotDefaultsToEmpty(t *testing.T) {
	cfg, err := config.NewConfig(context.Background(), envconfig.MapLookuper(map[string]string{
		"FEATURE_ENABLE_GRAFANA_ALERTS": "true",
		"GRAFANA_SLACK_WEBHOOK_URL":     "https://example.com/webhook",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.FeatureFlags.GrafanaAlertPilotTeams) != 0 {
		t.Fatalf("expected no Grafana alert pilot teams, got %v", cfg.FeatureFlags.GrafanaAlertPilotTeams)
	}
}
