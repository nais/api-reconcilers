package audit

import (
	"context"
	"fmt"

	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/nais/pgrator/pkg/api/datav1"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func (r *auditLogReconciler) teamHasPostgresWithAuditEnabled(ctx context.Context, naisTeam *protoapi.Team, env *protoapi.TeamEnvironment, log logrus.FieldLogger) (bool, error) {
	c, exists := r.k8sClients[env.EnvironmentName]
	if !exists {
		return false, fmt.Errorf("no Kubernetes client for environment %q", env.EnvironmentName)
	}

	gvr := datav1.GroupVersion.WithResource("postgres")

	unstructuredList, err := c.DynamicClient.Resource(gvr).Namespace(naisTeam.Slug).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("unable to list Postgres clusters in namespace %s: %w", naisTeam.Slug, err)
	}

	for _, postgres := range unstructuredList.Items {
		content := postgres.UnstructuredContent()
		value, _, err := unstructured.NestedBool(content, "spec", "cluster", "audit", "enabled")
		if err != nil {
			return false, fmt.Errorf("audit flag is not a bool: %w", err)
		}
		if value {
			return true, nil
		}
	}

	return false, nil
}
