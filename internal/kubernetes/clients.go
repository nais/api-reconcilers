package kubernetes

import (
	"fmt"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type K8sClients map[string]clients

type clients struct {
	Clientset     kubernetes.Interface
	DynamicClient dynamic.Interface
}

func Clients(tenantName string, clusters []string, onpremClusters []OnpremCluster) (K8sClients, error) {
	clusterConfig, err := getClusterConfigMap(tenantName, clusters, onpremClusters)
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
