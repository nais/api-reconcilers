package reconciler

import (
	"context"

	"github.com/nais/api-reconcilers/internal/gcp"
	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	Azure struct {
		// GroupNamePrefix will be prepended all groups created in Azure.
		GroupNamePrefix string `env:"AZURE_GROUP_NAME_PREFIX,default=nais-team-"`
	}

	DependencyTrack struct {
		// Endpoint URL to the DependencyTrack API.
		Endpoint string `env:"DEPENDENCYTRACK_ENDPOINT"`

		// Username The username to use when authenticating with DependencyTrack.
		Username string `env:"DEPENDENCYTRACK_USERNAME"`

		// Password The password to use when authenticating with DependencyTrack.
		Password string `env:"DEPENDENCYTRACK_PASSWORD"`
	}

	GCP struct {
		// BillingAccount The ID of the billing account that each team project will be assigned to.
		//
		// Example: `billingAccounts/123456789ABC`
		BillingAccount string `env:"GCP_BILLING_ACCOUNT"`

		// Clusters A JSON-encoded value describing the GCP clusters to use. Refer to the README for the format.
		Clusters gcp.Clusters `env:"GCP_CLUSTERS"`

		// CnrmRole The name of the custom CNRM role that is used when creating role bindings for the GCP projects of each
		// team. The value must also contain the organization ID.
		//
		// Example: `organizations/<org_id>/roles/CustomCNRMRole`, where `<org_id>` is a numeric ID.
		CnrmRole string `env:"GCP_CNRM_ROLE"`

		// CnrmServiceAccountID The ID of the service account used by CNRM to manage GCP resources.
		CnrmServiceAccountID string `env:"GCP_CNRM_SERVICE_ACCOUNT_ID,default=nais-sa-cnrm"`

		// WorkloadIdentityPoolName The name of the workload identity pool used in the management project.
		//
		// Example: projects/{project_number}/locations/global/workloadIdentityPools/{workload_identity_pool_id}
		WorkloadIdentityPoolName string `env:"GCP_WORKLOAD_IDENTITY_POOL_NAME"`
	}

	GitHub struct {
		// AuthEndpoint Endpoint URL to the GitHub auth component.
		AuthEndpoint string `env:"GITHUB_AUTH_ENDPOINT"`

		// Organization The GitHub organization slug for the tenant.
		Organization string `env:"GITHUB_ORG,default=navikt-dev"`
	}

	GRPC struct {
		// Target The target address for the gRPC server.
		Target string `env:"GRPC_TARGET,default=127.0.0.1:3001"`

		// InsecureGRPC bypasses authentication, use for development purposes only.
		Insecure bool `env:"INSECURE_GRPC"`
	}

	NaisDeploy struct {
		// Endpoint URL to the NAIS deploy key provisioning endpoint
		Endpoint string `env:"NAIS_DEPLOY_ENDPOINT,default=http://localhost:8080/api/v1/provision"`

		// ProvisionKey The API key used when provisioning deploy keys on behalf of NAIS teams.
		ProvisionKey string `env:"NAIS_DEPLOY_PROVISION_KEY"`
	}

	NaisNamespace struct {
		// AzureEnabled When set to true teams-backend will send the Azure group ID of the team, if it has been created by
		// the Azure AD group reconciler, to naisd when creating a namespace for the NAIS team.
		AzureEnabled bool `env:"NAIS_NAMESPACE_AZURE_ENABLED"`
	}

	// GoogleManagementProjectID The ID of the NAIS management project in the tenant organization in GCP.
	GoogleManagementProjectID string `env:"GOOGLE_MANAGEMENT_PROJECT_ID"`

	// ListenAddress The host:port combination used by the http server.
	ListenAddress string `env:"LISTEN_ADDRESS,default=127.0.0.1:3005"`

	// LogFormat Customize the log format. Can be "text" or "json".
	LogFormat string `env:"LOG_FORMAT,default=json"`

	// LogLevel The log level used in teams-backend.
	LogLevel string `env:"LOG_LEVEL,default=info"`

	// TenantDomain The domain for the tenant.
	TenantDomain string `env:"TENANT_DOMAIN,default=example.com"`

	// TenantName The name of the tenant.
	TenantName string `env:"TENANT_NAME,default=example"`

	// Reconcilers to enable when first registering the reconciler
	ReconcilersToEnable []string `env:"RECONCILERS_TO_ENABLE"`

	// PubsubSubscriptionID The ID of the Pub/Sub subscription used to listen for events from the NAIS API.
	PubsubSubscriptionID string `env:"PUBSUB_SUBSCRIPTION_ID,default=api-reconcilers-api-events"`

	// PubSubProjectID The ID of the Pub/Sub project used to listen for events from the NAIS API. Defaults to GoogleManagementProjectID.
	PubSubProjectID string `env:"PUBSUB_PROJECT_ID,default=$GOOGLE_MANAGEMENT_PROJECT_ID"`
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
