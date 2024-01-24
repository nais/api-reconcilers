package reconciler

import (
	"context"

	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	ListenAddress             string `env:"LISTEN_ADDRESS,default=127.0.0.1:3005"`
	LogFormat                 string `env:"LOG_FORMAT,default=json"`
	LogLevel                  string `env:"LOG_LEVEL,default=info"`
	InsecureGRPC              bool   `env:"INSECURE_GRPC"`
	GRPCTarget                string `env:"GRPC_TARGET,default=127.0.0.1:3001"`
	GitHubOrg                 string `env:"GITHUB_ORG,default=navikt-dev"`
	GitHubAuthEndpoint        string `env:"GITHUB_AUTH_ENDPOINT"`
	GoogleManagementProjectID string `env:"GOOGLE_MANAGEMENT_PROJECT_ID"`
	TenantDomain              string `env:"TENANT_DOMAIN,default=example.com"`
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
