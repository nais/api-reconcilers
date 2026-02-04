package kubernetes

import (
	"fmt"

	"github.com/nais/api-reconcilers/internal/kubernetes/fake"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	k8s_fake "k8s.io/client-go/kubernetes/fake"
)

type K8sClients map[string]clients

type clients struct {
	Clientset     kubernetes.Interface
	DynamicClient dynamic.Interface
}

func Clients(tenantName string, clusters []string, clusterAliases map[string]string) (K8sClients, error) {
	clusterConfig, err := getClusterConfigMap(tenantName, clusters, clusterAliases)
	if err != nil {
		return nil, fmt.Errorf("creating cluster config map: %w", err)
	}

	clientSets := make(K8sClients)
	for cluster, restConfig := range clusterConfig {
		clientSet, err := kubernetes.NewForConfig(restConfig)
		if err != nil {
			return nil, fmt.Errorf("create clientset: %w", err)
		}

		dynamicClient, err := dynamic.NewForConfig(restConfig)
		if err != nil {
			return nil, fmt.Errorf("create dynamic client: %w", err)
		}

		clientSets[cluster] = clients{
			Clientset:     clientSet,
			DynamicClient: dynamicClient,
		}
	}

	return clientSets, nil
}

func FakeClients(envName string, objects ...runtime.Object) K8sClients {
	clientSets := make(K8sClients)
	clientSets[envName] = clients{
		Clientset:     k8s_fake.NewClientset(),
		DynamicClient: fake.NewDynamicClient(objects...),
	}
	return clientSets
}
