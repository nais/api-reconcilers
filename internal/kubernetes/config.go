package kubernetes

import (
	"fmt"
	"net/http"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"
)

type OnpremCluster struct {
	// Name is the name of the clusters, for instance "prod-fss"
	Name string

	// Host is the hostname of the cluster, for instance "https://apiserver.dev-fss.nais.io"
	Host string

	// Token is the bearer token used to authenticate with the cluster.
	Token string
}

func (c *OnpremCluster) EnvDecode(value string) error {
	if value == "" {
		return nil
	}

	parts := strings.Split(value, "|")
	if len(parts) != 3 {
		return fmt.Errorf(`invalid onprem cluster entry: %q. Must be on format "name|host|token"`, value)
	}

	name := strings.TrimSpace(parts[0])
	if name == "" {
		return fmt.Errorf("invalid onprem cluster entry: %q. Name must not be empty", value)
	}

	host := strings.TrimSpace(parts[1])
	if host == "" {
		return fmt.Errorf("invalid onprem cluster entry: %q. Host must not be empty", value)
	}

	token := strings.TrimSpace(parts[2])
	if token == "" {
		return fmt.Errorf("invalid onprem cluster entry: %q. Token must not be empty", value)
	}

	*c = OnpremCluster{
		Name:  name,
		Host:  host,
		Token: token,
	}
	return nil
}

type clusterConfigMap map[string]*rest.Config

func getClusterConfigMap(tenant string, clusters []string, onpremClusters []OnpremCluster, clusterAliases map[string]string) (clusterConfigMap, error) {
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

	for _, cluster := range onpremClusters {
		configs[cluster.Name] = &rest.Config{
			Host:        cluster.Host,
			BearerToken: cluster.Token,
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: true,
			},
			WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
				return otelhttp.NewTransport(rt, otelhttp.WithServerName(cluster.Name))
			},
		}
	}
	return configs, nil
}
