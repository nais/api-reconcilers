package reconciler

import (
	"context"

	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	ListenAddress string `env:"LISTEN_ADDRESS,default=127.0.0.1:3000"`
	LogFormat     string `env:"LOG_FORMAT,default=json"`
	LogLevel      string `env:"LOG_LEVEL,default=info"`
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
