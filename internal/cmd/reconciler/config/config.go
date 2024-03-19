package config

import (
	"context"

	"github.com/nais/api-reconcilers/internal/gcp"
	"github.com/sethvargo/go-envconfig"
)

type FeatureFlags struct {
	// AttachSharedVpc enabled the shared vpc feature
	AttachSharedVpc bool `env:"FEATURE_ATTACH_SHARED_VPC"`
}

type Config struct {
	// Flags to enable new features
	FeatureFlags FeatureFlags

	Azure struct {
		// GroupNamePrefix will be prepended all groups created in Azure.
		GroupNamePrefix string `env:"AZURE_GROUP_NAME_PREFIX,default=nais-team-"`
	}

	DependencyTrack struct {
		// Endpoint URL to the DependencyTrack API.
		Endpoint string `env:"DEPENDENCYTRACK_ENDPOINT"`

		// Username The username to use when authenticating with DependencyTrack.
		Username string `env:"DEPENDENCYTRACK_USERNAME,default=nais-api-reconcilers"`

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

		// ServiceAccountEmail The email address to impersonate when using Google APIs
		ServiceAccountEmail string `env:"GCP_SERVICE_ACCOUNT_EMAIL"`

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

	PubSub struct {
		// SubscriptionID The ID of the Pub/Sub subscription used to listen for events from the NAIS API.
		SubscriptionID string `env:"PUBSUB_SUBSCRIPTION_ID,default=nais-api-reconcilers-api-events"`

		// ProjectID The ID of the Pub/Sub project used to listen for events from the NAIS API. Defaults to GoogleManagementProjectID.
		ProjectID string `env:"PUBSUB_PROJECT_ID,default=$GOOGLE_MANAGEMENT_PROJECT_ID"`
	}

	Google struct {
		// AdminServiceAccountEmail The email address of the service account to impersonate when using Google Workspace Admin APIs
		AdminServiceAccountEmail string `env:"GOOGLE_ADMIN_SERVICE_ACCOUNT_EMAIL"`

		// AdminUserEmail The email address to impersonate during Google Admin Workspace operations.
		AdminUserEmail string `env:"GOOGLE_ADMIN_USER_EMAIL"`
	}

	// GoogleManagementProjectID The ID of the NAIS management project in the tenant organization in GCP.
	GoogleManagementProjectID string `env:"GOOGLE_MANAGEMENT_PROJECT_ID"`

	// ListenAddress The host:port combination used by the http server.
	ListenAddress string `env:"LISTEN_ADDRESS,default=127.0.0.1:3005"`

	// LogFormat Customize the log format. Can be "text" or "json".
	LogFormat string `env:"LOG_FORMAT,default=json"`

	// LogLevel The log level used in api-reconcilers
	LogLevel string `env:"LOG_LEVEL,default=info"`

	// TenantDomain The domain for the tenant.
	TenantDomain string `env:"TENANT_DOMAIN,default=example.com"`

	// TenantName The name of the tenant.
	TenantName string `env:"TENANT_NAME,default=example"`

	// Reconcilers to enable when first registering the reconciler
	ReconcilersToEnable []string `env:"RECONCILERS_TO_ENABLE"`
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
