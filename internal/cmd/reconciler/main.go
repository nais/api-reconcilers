package reconciler

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/nais/api-reconcilers/internal/logger"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	azure_group_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/azure/group"
	dependencytrack_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/dependencytrack"
	github_team_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/github/team"
	google_gar_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/gar"
	google_gcp_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/gcp"
	google_workspace_admin_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/workspace_admin"
	nais_deploy_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/nais/deploy"
	nais_namespace_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/nais/namespace"
	"github.com/nais/api/pkg/apiclient"
	"github.com/sethvargo/go-envconfig"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	exitCodeSuccess = iota
	exitCodeLoggerError
	exitCodeRunError
	exitCodeConfigError
	exitCodeEnvFileError
)

func Run(ctx context.Context) {
	log := logrus.StandardLogger()

	if fileLoaded, err := loadEnvFile(); err != nil {
		log.WithError(err).Errorf("error when loading .env file")
		os.Exit(exitCodeEnvFileError)
	} else if fileLoaded {
		log.Infof("loaded .env file")
	}

	cfg, err := NewConfig(ctx, envconfig.OsLookuper())
	if err != nil {
		log.WithError(err).Errorf("error when processing configuration")
		os.Exit(exitCodeConfigError)
	}

	appLogger, err := logger.New(cfg.LogFormat, cfg.LogLevel)
	if err != nil {
		log.WithError(err).Errorf("error when creating application logger")
		os.Exit(exitCodeLoggerError)
	}

	err = run(ctx, cfg, appLogger)
	if err != nil {
		appLogger.WithError(err).Errorf("error in run()")
		os.Exit(exitCodeRunError)
	}

	os.Exit(exitCodeSuccess)
}

func run(ctx context.Context, cfg *Config, log logrus.FieldLogger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx, signalStop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer signalStop()

	_, promRegistry, err := newMeterProvider()
	if err != nil {
		return err
	}

	wg, ctx := errgroup.WithContext(ctx)
	wg.Go(func() error {
		return runHttpServer(ctx, cfg.ListenAddress, promRegistry, log)
	})

	opts := []grpc.DialOption{
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	}
	if cfg.GRPC.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	client, err := apiclient.New(cfg.GRPC.Target, opts...)
	if err != nil {
		return err
	}

	reconcilerManager := reconcilers.NewManager(client, log)

	azureGroupReconciler := azure_group_reconciler.New(ctx, cfg.TenantDomain, client)

	githubReconciler, err := github_team_reconciler.New(ctx, cfg.GitHub.Organization, cfg.GitHub.AuthEndpoint, cfg.GoogleManagementProjectID)
	if err != nil {
		return err
	}

	googleWorkspaceAdminReconciler, err := google_workspace_admin_reconciler.New(ctx, cfg.GoogleManagementProjectID, cfg.TenantDomain)
	if err != nil {
		return err
	}

	naisDeployReconciler, err := nais_deploy_reconciler.New(cfg.NaisDeploy.Endpoint, cfg.NaisDeploy.ProvisionKey)
	if err != nil {
		return err
	}

	googleGcpReconciler, err := google_gcp_reconciler.New(ctx, cfg.GCP.Clusters, cfg.GoogleManagementProjectID, cfg.TenantDomain, cfg.TenantName, cfg.GCP.CnrmRole, cfg.GCP.BillingAccount, cfg.GCP.CnrmServiceAccountID)
	if err != nil {
		return err
	}

	garReconciler, err := google_gar_reconciler.New(ctx, cfg.GoogleManagementProjectID, cfg.TenantDomain, cfg.GCP.WorkloadIdentityPoolName)
	if err != nil {
		return err
	}

	namespaceReconciler, err := nais_namespace_reconciler.New(ctx, cfg.GCP.Clusters, cfg.TenantDomain, cfg.GoogleManagementProjectID, cfg.GCP.CnrmServiceAccountID, cfg.NaisNamespace.AzureEnabled, cfg.OnpremClusters)
	if err != nil {
		return err
	}

	dependencyTrackReconciler, err := dependencytrack_reconciler.New(ctx, cfg.DependencyTrack.Endpoint, cfg.DependencyTrack.Username, cfg.DependencyTrack.Password)
	if err != nil {
		log.WithField("reconciler", "dependencytrack").WithError(err).Errorf("error when creating reconciler")
	} else {
		reconcilerManager.Register(dependencyTrackReconciler)
	}

	reconcilerManager.Register(azureGroupReconciler)
	reconcilerManager.Register(githubReconciler)
	reconcilerManager.Register(googleWorkspaceAdminReconciler)
	reconcilerManager.Register(naisDeployReconciler)
	reconcilerManager.Register(googleGcpReconciler)
	reconcilerManager.Register(garReconciler)
	reconcilerManager.Register(namespaceReconciler)

	if err = reconcilerManager.Run(ctx, time.Minute*30); err != nil {
		return err
	}

	return nil
}

func loadEnvFile() (fileLoaded bool, err error) {
	if _, err = os.Stat(".env"); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	if err = godotenv.Load(".env"); err != nil {
		return false, err
	}

	return true, nil
}
