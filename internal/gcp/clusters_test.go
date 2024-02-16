package gcp_test

import (
	"testing"

	"github.com/nais/api-reconcilers/internal/gcp"
)

func TestDecodeJSONToClusters(t *testing.T) {
	clusters := make(gcp.Clusters)

	t.Run("empty string", func(t *testing.T) {
		err := clusters.EnvDecode("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(clusters) != 0 {
			t.Fatalf("expected 0 clusters, got %d", len(clusters))
		}
	})

	t.Run("empty JSON object", func(t *testing.T) {
		err := clusters.EnvDecode("{}")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(clusters) != 0 {
			t.Fatalf("expected 0 clusters, got %d", len(clusters))
		}
	})

	t.Run("JSON with clusters", func(t *testing.T) {
		err := clusters.EnvDecode(`{
			"env1": {"teams_folder_id": "123", "project_id": "some-id-123"},
			"env2": {"teams_folder_id": "456", "project_id": "some-id-456"}
		}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		cluster, exists := clusters["env1"]
		if !exists {
			t.Fatalf("expected cluster 'env1' to exist")
		}

		if cluster.TeamsFolderID != 123 {
			t.Fatalf("expected cluster 'env1' to have teams_folder_id 123, got %d", cluster.TeamsFolderID)
		}

		if expected := "some-id-123"; cluster.ProjectID != expected {
			t.Fatalf("expected cluster 'env1' to have project ID %q, got %q", expected, cluster.TeamsFolderID)
		}

		cluster, exists = clusters["env2"]
		if !exists {
			t.Fatalf("expected cluster 'env2' to exist")
		}

		if cluster.TeamsFolderID != 456 {
			t.Fatalf("expected cluster 'env2' to have teams_folder_id 456, got %d", cluster.TeamsFolderID)
		}

		if expected := "some-id-456"; cluster.ProjectID != expected {
			t.Fatalf("expected cluster 'env2' to have project ID %q, got %q", expected, cluster.TeamsFolderID)
		}
	})
}
