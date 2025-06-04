package nais_namespace_reconciler

import (
	"context"
	"fmt"
	"strings"

	cnrmbeta1 "github.com/GoogleCloudPlatform/k8s-config-connector/operator/pkg/apis/core/v1beta1"
	"github.com/google/uuid"
	"github.com/nais/api-reconcilers/internal/kubernetes"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/iterator"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	corev1Typed "k8s.io/client-go/kubernetes/typed/core/v1"
	rbacTypedV1 "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/utils/ptr"
)

const reconcilerName = "nais:namespace"

var ErrDeleteRequiredNamespace = fmt.Errorf("namespace is required, cannot be deleted")

type OptFunc func(*naisNamespaceReconciler)

type naisNamespaceReconciler struct {
	k8sClients kubernetes.K8sClients
}

func New(ctx context.Context, k8sClients kubernetes.K8sClients, opts ...OptFunc) (reconcilers.Reconciler, error) {
	r := &naisNamespaceReconciler{
		k8sClients: k8sClients,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r, nil
}

func (r *naisNamespaceReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "NAIS namespace",
		Description: "Create NAIS namespaces for the Console teams.",
		MemberAware: false,
	}
}

func (r *naisNamespaceReconciler) Name() string {
	return reconcilerName
}

func (r *naisNamespaceReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	if naisTeam.GoogleGroupEmail == nil {
		return fmt.Errorf("no Google Workspace group exists for team %q yet", naisTeam.Slug)
	}

	// Since we do not have a good way to query the GCP project for a team we are building a local cache here.
	// This is used to label namespaces in fss clusters for use with team logs.
	gcpProjectIdCache := map[string]*string{}
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})
	for it.Next() {
		env := it.Value()
		gcpProjectIdCache[env.EnvironmentName] = env.GcpProjectId
	}

	it = iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})
	for it.Next() {
		env := it.Value()

		c, exists := r.k8sClients[env.EnvironmentName]
		if !exists {
			log.Errorf("No Kubernetes client for environment %q", env.EnvironmentName)
			continue
		}

		log = log.WithField("environment", env.EnvironmentName)

		var gcpProjectIdOverride *string
		if env.EnvironmentName == "ci-fss" {
			gcpProjectIdOverride = gcpProjectIdCache["ci-gcp"]
		} else if env.EnvironmentName == "dev-fss" {
			gcpProjectIdOverride = gcpProjectIdCache["dev-gcp"]
		} else if env.EnvironmentName == "prod-fss" {
			gcpProjectIdOverride = gcpProjectIdCache["prod-gcp"]
		}

		if err := r.ensureNamespace(ctx, naisTeam, env, gcpProjectIdOverride, c.Clientset.CoreV1().Namespaces(), log); err != nil {
			return fmt.Errorf("ensure namespace for project %q in environment %q: %w", ptr.Deref(env.GcpProjectId, ""), env.EnvironmentName, err)
		}

		if err := r.ensurePgNamespace(ctx, naisTeam, env, c.Clientset.CoreV1().Namespaces(), log); err != nil {
			return fmt.Errorf("ensure pg namespace for team %s in environment %q: %w", naisTeam.Slug, env.EnvironmentName, err)
		}

		if err := r.ensureServiceAccount(ctx, naisTeam, c.Clientset.CoreV1().ServiceAccounts(naisTeam.Slug), log); err != nil {
			return fmt.Errorf("ensure service account in namespace %q in environment %q: %w", naisTeam.Slug, env.EnvironmentName, err)
		}

		if err := r.ensureSARolebinding(ctx, naisTeam, c.Clientset.RbacV1().RoleBindings(naisTeam.Slug), log); err != nil {
			return fmt.Errorf("ensure service account rolebinding in namespace %q in environment %q: %w", naisTeam.Slug, env.EnvironmentName, err)
		}

		if err := r.ensureTeamRolebinding(ctx, naisTeam, c.Clientset.RbacV1().RoleBindings(naisTeam.Slug), "nais:developer", fmt.Sprintf("team-%s-naisdeveloper", naisTeam.Slug), log); err != nil {
			return fmt.Errorf("ensure team rolebinding in namespace %q in environment %q: %w", naisTeam.Slug, env.EnvironmentName, err)
		}

		if err := r.ensureTeamRolebinding(ctx, naisTeam, c.Clientset.RbacV1().RoleBindings("pg-"+naisTeam.Slug), "postgres-operator:users:view", fmt.Sprintf("team-%s-pgviewer", naisTeam.Slug), log); err != nil {
			return fmt.Errorf("ensure team rolebinding in namespace %q in environment %q: %w", naisTeam.Slug, env.EnvironmentName, err)
		}

		if !strings.HasSuffix(env.EnvironmentName, "-fss") {
			if err := r.ensureCNRMConfig(ctx, env, c.DynamicClient.Resource(cnrmbeta1.GroupVersion.WithResource("configconnectorcontexts")).Namespace(naisTeam.Slug), log); err != nil {
				return fmt.Errorf("ensure CNRM config in namespace %q in environment %q: %w", naisTeam.Slug, env.EnvironmentName, err)
			}
		} else {
			log.Debug("Skipping CNRM config for FSS")
		}

		if err := r.ensureResourceQuota(ctx, naisTeam, c.Clientset.CoreV1().ResourceQuotas(naisTeam.Slug), log); err != nil {
			return fmt.Errorf("ensure resource quota in namespace %q in environment %q: %w", naisTeam.Slug, env.EnvironmentName, err)
		}
	}

	return it.Err()
}

func (r *naisNamespaceReconciler) ensureNamespace(ctx context.Context, naisTeam *protoapi.Team, env *protoapi.TeamEnvironment, gcpProjectIdOverride *string, c corev1Typed.NamespaceInterface, log logrus.FieldLogger) error {
	var ns *corev1.Namespace

	log = log.WithField("slug", env.Slug).
		WithField("environment", env.EnvironmentName).
		WithField("gcpProjectId", env.GcpProjectId).
		WithField("gcpProjectIdOverride", gcpProjectIdOverride)

	ns, err := c.Get(ctx, naisTeam.Slug, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		ns.Name = naisTeam.Slug
		ns, err = c.Create(ctx, ns, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating namespace: %w", err)
		}
		log.Debug("Created namespace")
	} else if err != nil {
		return fmt.Errorf("getting namespace: %w", err)
	} else {
		log.Debug("Namespace already exists")
	}

	metav1.SetMetaDataAnnotation(&ns.ObjectMeta, "cnrm.cloud.google.com/project-id", ptr.Deref(env.GcpProjectId, ""))
	metav1.SetMetaDataAnnotation(&ns.ObjectMeta, "replicator.nais.io/slackAlertsChannel", env.SlackAlertsChannel)
	metav1.SetMetaDataLabel(&ns.ObjectMeta, "team", naisTeam.Slug)
	metav1.SetMetaDataLabel(&ns.ObjectMeta, "nais.io/type", "workload")
	metav1.SetMetaDataLabel(&ns.ObjectMeta, "google-cloud-project", ptr.Deref(env.GcpProjectId, ""))

	if gcpProjectIdOverride != nil {
		metav1.SetMetaDataAnnotation(&ns.ObjectMeta, "cnrm.cloud.google.com/project-id", ptr.Deref(gcpProjectIdOverride, ""))
		metav1.SetMetaDataLabel(&ns.ObjectMeta, "google-cloud-project", ptr.Deref(gcpProjectIdOverride, ""))
	}

	_, err = c.Update(ctx, ns, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating namespace: %w", err)
	}

	log.Debug("Updated namespace")

	return nil
}

func (r *naisNamespaceReconciler) ensurePgNamespace(ctx context.Context, naisTeam *protoapi.Team, env *protoapi.TeamEnvironment, c corev1Typed.NamespaceInterface, log logrus.FieldLogger) error {
	var ns *corev1.Namespace
	pgNamespaceName := "pg-" + naisTeam.Slug

	log = log.WithField("slug", env.Slug).
		WithField("environment", env.EnvironmentName).
		WithField("pgNamespaceName", pgNamespaceName)

	ns, err := c.Get(ctx, pgNamespaceName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		ns.Name = pgNamespaceName
		ns, err = c.Create(ctx, ns, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating namespace: %w", err)
		}
		log.Debug("Created namespace")
	} else if err != nil {
		return fmt.Errorf("getting namespace: %w", err)
	} else {
		log.Debug("Namespace already exists")
	}

	metav1.SetMetaDataAnnotation(&ns.ObjectMeta, "replicator.nais.io/slackAlertsChannel", env.SlackAlertsChannel)
	metav1.SetMetaDataLabel(&ns.ObjectMeta, "team", naisTeam.Slug)
	metav1.SetMetaDataLabel(&ns.ObjectMeta, "nais.io/type", "postgres")

	_, err = c.Update(ctx, ns, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating namespace: %w", err)
	}

	log.Debug("Updated namespace")

	return nil
}

func (r *naisNamespaceReconciler) ensureServiceAccount(ctx context.Context, naisTeam *protoapi.Team, c corev1Typed.ServiceAccountInterface, log logrus.FieldLogger) error {
	name := fmt.Sprintf("serviceuser-%s", naisTeam.Slug)
	log = log.WithField("sa_name", name)
	sa, err := c.Get(ctx, name, metav1.GetOptions{})

	if errors.IsNotFound(err) {
		sa.Name = name
		_, err = c.Create(ctx, sa, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating service account: %w", err)
		}
		log.Debugf("Created service account")
	} else if err != nil {
		return fmt.Errorf("getting service account: %w", err)
	} else {
		log.Debugf("Service account already exists")
	}

	return nil
}

func (r *naisNamespaceReconciler) ensureSARolebinding(ctx context.Context, naisTeam *protoapi.Team, c rbacTypedV1.RoleBindingInterface, log logrus.FieldLogger) error {
	name := fmt.Sprintf("serviceuser-%s-naisdeveloper", naisTeam.Slug)
	log = log.WithField("rolebinding_name", name)
	rb, err := c.Get(ctx, name, metav1.GetOptions{})

	rb.RoleRef = v1.RoleRef{
		APIGroup: "rbac.authorization.k8s.io",
		Kind:     "ClusterRole",
		Name:     "nais:developer",
	}

	rb.Subjects = []v1.Subject{
		{
			Kind:      "ServiceAccount",
			Name:      fmt.Sprintf("serviceuser-%s", naisTeam.Slug),
			Namespace: naisTeam.Slug,
		},
	}

	if errors.IsNotFound(err) {
		rb.Name = name
		_, err = c.Create(ctx, rb, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating rolebinding %q: %w", name, err)
		}
		log.Debugf("Created rolebinding")
	} else if err != nil {
		return fmt.Errorf("getting rolebinding %q: %w", name, err)
	} else {
		log.Debugf("Rolebinding already exists")
		_, err := c.Update(ctx, rb, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("updating rolebinding: %w", err)
		}
	}

	return nil
}

func (r *naisNamespaceReconciler) ensureTeamRolebinding(ctx context.Context, naisTeam *protoapi.Team, c rbacTypedV1.RoleBindingInterface, targetRole, roleBindingName string, log logrus.FieldLogger) error {
	log = log.WithField("rolebinding_name", roleBindingName)
	rb, err := c.Get(ctx, roleBindingName, metav1.GetOptions{})

	rb.RoleRef = v1.RoleRef{
		APIGroup: "rbac.authorization.k8s.io",
		Kind:     "ClusterRole",
		Name:     targetRole,
	}

	rb.Subjects = []v1.Subject{
		{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Group",
			Name:     *naisTeam.GoogleGroupEmail,
		},
	}

	if naisTeam.EntraIdGroupId != nil {
		id, err := uuid.Parse(*naisTeam.EntraIdGroupId)
		if err != nil {
			return fmt.Errorf("unable to parse Azure group ID: %w", err)
		}
		rb.Subjects = append(rb.Subjects, v1.Subject{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Group",
			Name:     id.String(),
		})
	}

	if errors.IsNotFound(err) {
		rb.Name = roleBindingName
		_, err = c.Create(ctx, rb, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating rolebinding %q: %w", roleBindingName, err)
		}
		log.Debugf("Created rolebinding")
	} else if err != nil {
		return fmt.Errorf("getting rolebinding: %w", err)
	} else {
		log.Debugf("Rolebinding already exists")
		_, err := c.Update(ctx, rb, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("updating rolebinding %q: %w", roleBindingName, err)
		}
	}

	return nil
}

func (r *naisNamespaceReconciler) ensureCNRMConfig(ctx context.Context, env *protoapi.TeamEnvironment, c dynamic.ResourceInterface, log logrus.FieldLogger) error {
	if env.GcpProjectId == nil {
		log.Error("Skipping creation of CNRM config, GCP project ID is missing")
		return nil
	}

	const name = "configconnectorcontext.core.cnrm.cloud.google.com"

	existing, err := c.Get(ctx, name, metav1.GetOptions{})

	ccc := map[string]any{
		"apiVersion": "core.cnrm.cloud.google.com/v1beta1",
		"kind":       "ConfigConnectorContext",
		"metadata": map[string]any{
			"name": name,
		},
		"spec": map[string]any{
			"googleServiceAccount": fmt.Sprintf("nais-sa-cnrm@%s.iam.gserviceaccount.com", *env.GcpProjectId),
		},
	}

	if errors.IsNotFound(err) {
		cctx := &unstructured.Unstructured{
			Object: ccc,
		}
		_, err = c.Create(ctx, cctx, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating CNRM config: %w", err)
		}
		log.Debug("Created CNRM config")
	} else if err != nil {
		return fmt.Errorf("getting CNRM config: %w", err)
	} else {
		log.Debug("CNRM config already exists")
		existing.Object["spec"] = ccc["spec"]
		_, err := c.Update(ctx, existing, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("updating CNRM config: %w", err)
		}
		log.Debug("Updated CNRM config")
	}

	return nil
}

func (r *naisNamespaceReconciler) ensureResourceQuota(ctx context.Context, naisTeam *protoapi.Team, c corev1Typed.ResourceQuotaInterface, log logrus.FieldLogger) error {
	const quotaName = "nais-quota"

	_, err := c.Get(ctx, quotaName, metav1.GetOptions{})

	if errors.IsNotFound(err) {
		quota := &corev1.ResourceQuota{
			ObjectMeta: metav1.ObjectMeta{
				Name:      quotaName,
				Namespace: naisTeam.Slug,
			},
			Spec: corev1.ResourceQuotaSpec{
				Hard: corev1.ResourceList{
					corev1.ResourcePods: resource.MustParse("200"),
				},
			},
		}

		_, err := c.Create(ctx, quota, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating resource quota: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("getting resource quota: %w", err)
	} else {
		log.Debug("Resource quota already exists, skipping")
	}

	return nil
}

func (r *naisNamespaceReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	log = log.WithField("namespace", naisTeam.Slug)

	switch naisTeam.Slug {
	case "nais-system",
		"kube-system",
		"default",
		"kube-public":
		log.Warn("Namespace is not allowed to be deleted")
		return ErrDeleteRequiredNamespace
	}

	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})
	for it.Next() {
		env := it.Value()
		log = log.WithField("environment", env.EnvironmentName)

		c, exists := r.k8sClients[env.EnvironmentName]
		if !exists {
			log.Errorf("No Kubernetes client for environment")
			continue
		}

		err := r.deleteNamespace(ctx, naisTeam.Slug, c.Clientset.CoreV1().Namespaces(), log)
		if err != nil {
			log.WithError(err).Errorf("deleting namespace")
			continue
		}

		err = r.deleteNamespace(ctx, fmt.Sprintf("pg-%s", naisTeam.Slug), c.Clientset.CoreV1().Namespaces(), log)
		if err != nil {
			log.WithError(err).Errorf("deleting namespace")
			continue
		}
		log.Debugf("Deleted namespace")
	}

	return nil
}

func (r *naisNamespaceReconciler) deleteNamespace(ctx context.Context, namespace string, c corev1Typed.NamespaceInterface, log logrus.FieldLogger) error {
	err := c.Delete(ctx, namespace, metav1.DeleteOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			log.WithField("namespace", namespace).Errorf("Namespace not found")
			return nil
		}
		return err
	}

	return nil
}
