package reconciler

import (
	"context"

	"github.com/nais/api-reconcilers/internal/gcp"
	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	AzureEnabled              bool         `env:"NAIS_NAMESPACE_AZURE_ENABLED"`
	BillingAccount            string       `env:"GCP_BILLING_ACCOUNT"`
	CNRMRole                  string       `env:"GCP_CNRM_ROLE"`
	CNRMServiceAccountID      string       `env:"GCP_CNRM_SERVICE_ACCOUNT_ID,default=nais-sa-cnrm"`
	Clusters                  gcp.Clusters `env:"GCP_CLUSTERS"`
	GRPCTarget                string       `env:"GRPC_TARGET,default=127.0.0.1:3001"`
	GitHubAuthEndpoint        string       `env:"GITHUB_AUTH_ENDPOINT"`
	GitHubOrg                 string       `env:"GITHUB_ORG,default=navikt-dev"`
	GoogleManagementProjectID string       `env:"GOOGLE_MANAGEMENT_PROJECT_ID"`
	InsecureGRPC              bool         `env:"INSECURE_GRPC"`
	ListenAddress             string       `env:"LISTEN_ADDRESS,default=127.0.0.1:3005"`
	LogFormat                 string       `env:"LOG_FORMAT,default=json"`
	LogLevel                  string       `env:"LOG_LEVEL,default=info"`
	NaisDeployEndpoint        string       `env:"NAIS_DEPLOY_ENDPOINT,default=http://localhost:8080/api/v1/provision"`
	NaisDeployProvisionKey    string       `env:"NAIS_DEPLOY_PROVISION_KEY"`
	OnpremClusters            []string     `env:"ONPREM_CLUSTERS"`
	TenantDomain              string       `env:"TENANT_DOMAIN,default=example.com"`
	TenantName                string       `env:"TENANT_NAME,default=example"`
	WorkloadIdentityPoolName  string       `env:"GCP_WORKLOAD_IDENTITY_POOL_NAME"`
}

// NewConfig creates a new configuration instance from environment variables
func NewConfig(ctx context.Context, lookuper envconfig.Lookuper) (*Config, error) {
	cfg := &Config{}
	err := envconfig.ProcessWith(ctx, &envconfig.Config{
		Target:   cfg,
		Lookuper: lookuper,
	})
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
