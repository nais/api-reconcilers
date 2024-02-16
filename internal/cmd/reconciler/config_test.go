package reconciler_test

import (
	"context"
	"testing"

	"github.com/nais/api-reconcilers/internal/cmd/reconciler"
	"github.com/sethvargo/go-envconfig"
)

func TestNew(t *testing.T) {
	ctx := context.Background()
	lookuper := envconfig.MapLookuper(map[string]string{
		"GCP_CLUSTERS": `{"name":{"project_id":"some-id","teams_folder_id":"123456789"}}`,
	})
	cfg, err := reconciler.NewConfig(ctx, lookuper)
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
}
