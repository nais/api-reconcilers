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

	reconcilerManager := reconcilers.NewManager(ctx, client, cfg.ReconcilersToEnable, cfg.PubsubSubscriptionID, log)

	azureGroupReconciler := azure_group_reconciler.New(cfg.TenantDomain)

	githubReconciler, err := github_team_reconciler.New(ctx, cfg.GitHub.Organization, cfg.GitHub.AuthEndpoint, cfg.GoogleManagementProjectID)
	if err != nil {
		return err
	}

	googleWorkspaceAdminReconciler, err := google_workspace_admin_reconciler.New(ctx, cfg.GoogleManagementProjectID, cfg.TenantDomain)
	if err != nil {
		return err
	}

	deployReconciler, err := nais_deploy_reconciler.New(cfg.NaisDeploy.Endpoint, cfg.NaisDeploy.ProvisionKey)
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

	dependencyTrackReconciler, err := dependencytrack_reconciler.New(cfg.DependencyTrack.Endpoint, cfg.DependencyTrack.Username, cfg.DependencyTrack.Password)
	if err != nil {
		log.WithField("reconciler", "dependencytrack").WithError(err).Errorf("error when creating reconciler")
	}

	// The reconcilers will be run in the order they are added to the manager
	reconcilerManager.AddReconciler(githubReconciler)
	reconcilerManager.AddReconciler(azureGroupReconciler)
	reconcilerManager.AddReconciler(googleWorkspaceAdminReconciler)
	reconcilerManager.AddReconciler(googleGcpReconciler)
	reconcilerManager.AddReconciler(namespaceReconciler)
	reconcilerManager.AddReconciler(deployReconciler)
	reconcilerManager.AddReconciler(garReconciler)

	if dependencyTrackReconciler != nil {
		reconcilerManager.AddReconciler(dependencyTrackReconciler)
	}

	if err := reconcilerManager.RegisterReconcilersWithAPI(ctx); err != nil {
		return err
	}

	for i := 0; i < 10; i++ {
		wg.Go(func() error {
			reconcilerManager.Run(ctx)
			return nil
		})
	}

	wg.Go(func() error {
		return reconcilerManager.ListenForEvents(ctx)
	})

	if err = reconcilerManager.SyncAllTeams(ctx, time.Minute*30); err != nil {
		return err
	}

	reconcilerManager.Close()
	return wg.Wait()
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
