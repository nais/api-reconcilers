package kubernetes

import (
	"fmt"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"
)

type clusterConfigMap map[string]*rest.Config

func getClusterConfigMap(tenant string, clusters []string, clusterAliases map[string]string) (clusterConfigMap, error) {
	configs := clusterConfigMap{}

	for _, cluster := range clusters {
		domain := cluster
		for alias, target := range clusterAliases { // TODO: remove this when legacy migration is done
			if cluster == target {
				domain = alias
				break
			}
		}
		configs[cluster] = &rest.Config{
			Host: fmt.Sprintf("https://apiserver.%s.%s.cloud.nais.io", domain, tenant),
			AuthProvider: &api.AuthProviderConfig{
				Name: googleAuthPlugin,
			},
			WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
				return otelhttp.NewTransport(rt, otelhttp.WithServerName(cluster))
			},
		}
	}

	return configs, nil
}
