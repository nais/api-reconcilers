package reconciler

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/go-openapi/strfmt"
	grafana_client "github.com/grafana/grafana-openapi-client-go/client"
	"github.com/joho/godotenv"
	"github.com/nais/api-reconcilers/internal/cmd/reconciler/config"
	"github.com/nais/api-reconcilers/internal/kubernetes"
	"github.com/nais/api-reconcilers/internal/logger"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	azure_group_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/azure/group"
	dependencytrack_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/dependencytrack"
	github_team_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/github/team"
	google_audit_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/audit"
	google_cdn_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/cdn"
	google_gar_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/gar"
	google_gcp_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/gcp"
	google_workspace_admin_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/workspace_admin"
	grafana_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/grafana"
	namespace_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/namespace"
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

	cfg, err := config.NewConfig(ctx, envconfig.OsLookuper())
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

func run(ctx context.Context, cfg *config.Config, log logrus.FieldLogger) error {
	ctx, signalStop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer signalStop()

	start := time.Now()

	_, promRegistry, err := newMeterProvider()
	if err != nil {
		return fmt.Errorf("error when creating meter provider: %w", err)
	}
	log.WithField("duration", time.Since(start).String()).Debug("Created meter provider")

	wg, ctx := errgroup.WithContext(ctx)
	wg.Go(func() error {
		defer log.Debug("Done running main http server goroutine")
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
		return fmt.Errorf("error when creating API client: %w", err)
	}
	log.WithField("duration", time.Since(start).String()).Debug("Created API client")

	reconcilerManager := reconcilers.NewManager(ctx, client, cfg.ReconcilersToEnable, cfg.PubSub.SubscriptionID, cfg.PubSub.ProjectID, log)
	log.WithField("duration", time.Since(start).String()).Debug("Created reconciler manager")

	azureGroupReconciler := azure_group_reconciler.New(ctx, cfg.TenantDomain, cfg.Azure.GroupNamePrefix)
	log.WithField("duration", time.Since(start).String()).Debug("Created Azure group reconciler")

	githubReconciler, err := github_team_reconciler.New(ctx, cfg.GitHub.Organization, cfg.GitHub.AuthEndpoint, cfg.GCP.ServiceAccountEmail)
	if err != nil {
		return fmt.Errorf("error when creating GitHub reconciler: %w", err)
	}
	log.WithField("duration", time.Since(start).String()).Debug("Created GitHub reconciler")

	googleWorkspaceAdminReconciler, err := google_workspace_admin_reconciler.New(ctx, cfg.Google.AdminServiceAccountEmail, cfg.Google.AdminUserEmail, cfg.TenantDomain)
	if err != nil {
		return fmt.Errorf("error when creating Google Workspace Admin reconciler: %w", err)
	}
	log.WithField("duration", time.Since(start).String()).Debug("Created Google Workspace Admin reconciler")

	googleGcpReconciler, err := google_gcp_reconciler.New(ctx, cfg.GCP.Clusters, cfg.GCP.ServiceAccountEmail, cfg.TenantDomain, cfg.TenantName, cfg.GCP.BillingAccount, cfg.ClusterAlias, cfg.FeatureFlags)
	if err != nil {
		return fmt.Errorf("error when creating Google GCP reconciler: %w", err)
	}
	log.WithField("duration", time.Since(start).String()).Debug("Created Google GCP reconciler")

	garReconciler, err := google_gar_reconciler.New(ctx, cfg.GCP.ServiceAccountEmail, cfg.GoogleManagementProjectID, cfg.GCP.WorkloadIdentityPoolName)
	if err != nil {
		return fmt.Errorf("error when creating Google GAR reconciler: %w", err)
	}
	log.WithField("duration", time.Since(start).String()).Debug("Created Google GAR reconciler")

	k8sClients, err := kubernetes.Clients(cfg.TenantName, slices.Sorted(maps.Keys(cfg.GCP.Clusters)), cfg.ClusterAlias)
	if err != nil {
		return fmt.Errorf("error when creating Kubernetes clients: %w", err)
	}

	namespaceReconciler, err := namespace_reconciler.New(ctx, k8sClients)
	if err != nil {
		return fmt.Errorf("error when creating NAIS namespace reconciler: %w", err)
	}
	log.WithField("duration", time.Since(start).String()).Debug("Created NAIS namespace reconciler")

	grafanaURL, err := url.Parse(cfg.Grafana.Endpoint)
	if err != nil {
		return fmt.Errorf("error when parsing Grafana endpoint: %w", err)
	}
	log.WithField("duration", time.Since(start).String()).Debug("Parsed Grafana endpoint")

	grafanaClient := grafana_client.NewHTTPClientWithConfig(strfmt.Default, &grafana_client.TransportConfig{
		Host:      grafanaURL.Host,
		Schemes:   []string{grafanaURL.Scheme},
		BasePath:  grafanaURL.Path,
		BasicAuth: url.UserPassword(cfg.Grafana.Username, cfg.Grafana.Password),
	})

	grafanaReconciler := grafana_reconciler.New(
		grafanaClient.Users,
		grafanaClient.Teams,
		grafanaClient.AccessControl,
		grafanaClient.ServiceAccounts,
		grafanaClient.AdminUsers,
		grafanaClient.Provisioning,
		cfg.FeatureFlags,
		cfg.Grafana.SlackWebhookURL,
	)
	log.WithField("duration", time.Since(start).String()).Debug("Created Grafana reconciler")

	dependencyTrackReconciler, err := dependencytrack_reconciler.New(cfg.DependencyTrack.Endpoint, cfg.DependencyTrack.Username, cfg.DependencyTrack.Password)
	if err != nil {
		log.WithField("reconciler", "dependencytrack").WithError(err).Errorf("error when creating reconciler")
	}
	log.WithField("duration", time.Since(start).String()).Debug("Created DependencyTrack reconciler")

	cdnReconciler, err := google_cdn_reconciler.New(ctx, cfg.GCP.ServiceAccountEmail, cfg.GoogleManagementProjectID, cfg.TenantName, cfg.GCP.WorkloadIdentityPoolName)
	if err != nil {
		log.WithField("reconciler", "cdn").WithError(err).Errorf("error when creating reconciler")
	}
	log.WithField("duration", time.Since(start).String()).Debug("Created CDN reconciler")

	auditLogReconciler, err := google_audit_reconciler.New(ctx, k8sClients, cfg.GCP.ServiceAccountEmail, google_audit_reconciler.Config{
		ProjectID: cfg.AuditLog.ProjectID,
		Location:  cfg.AuditLog.Location,
	})
	if err != nil {
		log.WithField("reconciler", "audit_log").WithError(err).Errorf("error when creating reconciler")
	}
	log.WithField("duration", time.Since(start).String()).Debug("Created Audit Log reconciler")

	// The reconcilers will be run in the order they are added to the manager
	reconcilerManager.AddReconciler(githubReconciler)
	reconcilerManager.AddReconciler(azureGroupReconciler)
	reconcilerManager.AddReconciler(googleWorkspaceAdminReconciler)
	reconcilerManager.AddReconciler(googleGcpReconciler)
	reconcilerManager.AddReconciler(namespaceReconciler)
	reconcilerManager.AddReconciler(garReconciler)
	reconcilerManager.AddReconciler(cdnReconciler)
	if auditLogReconciler != nil {
		reconcilerManager.AddReconciler(auditLogReconciler)
	}
	reconcilerManager.AddReconciler(grafanaReconciler)

	if dependencyTrackReconciler != nil {
		reconcilerManager.AddReconciler(dependencyTrackReconciler)
	}
	log.WithField("duration", time.Since(start).String()).Debug("Added reconcilers to manager")

	if err := reconcilerManager.RegisterReconcilersWithAPI(ctx); err != nil {
		return fmt.Errorf("error when registering reconcilers with API: %w", err)
	}
	log.WithField("duration", time.Since(start).String()).Debug("Registered reconcilers with API")

	for i := range 10 {
		wg.Go(func() error {
			defer log.Debugf("Done running reconciler %v", i)
			reconcilerManager.Run(ctx)
			return nil
		})
	}

	wg.Go(func() error {
		defer log.Debug("Done listening for pubsub events")
		reconcilerManager.ListenForEvents(ctx)
		return nil
	})

	if err = reconcilerManager.SyncAllTeams(ctx, time.Minute*30); err != nil {
		return fmt.Errorf("error when syncing all teams: %w", err)
	}
	log.WithField("duration", time.Since(start).String()).Debug("Synced all teams")

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
