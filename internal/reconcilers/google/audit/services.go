package audit

import (
	"context"
	"fmt"

	logging "cloud.google.com/go/logging/apiv2"
	"github.com/nais/api-reconcilers/internal/google_token_source"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
	monitoring "google.golang.org/api/monitoring/v3"
	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1"
)

// gcpServices creates and configures all necessary GCP services.
func gcpServices(ctx context.Context, serviceAccountEmail string) (*Services, error) {
	ts, err := google_token_source.GcpTokenSource(ctx, serviceAccountEmail)
	if err != nil {
		return nil, fmt.Errorf("get delegated token source: %w", err)
	}

	opts := []option.ClientOption{
		option.WithTokenSource(ts),
	}

	logAdminService, err := logging.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve Log Admin service: %w", err)
	}

	logConfigService, err := logging.NewConfigClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve Log Config service: %w", err)
	}

	iamService, err := iam.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve IAM service service: %w", err)
	}

	sqlAdminService, err := sqladmin.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve SQL admin service: %w", err)
	}

	cloudResourceManagerService, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve Cloud Resource Manager service: %w", err)
	}

	monitoringService, err := monitoring.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve Monitoring service: %w", err)
	}

	return &Services{
		LogAdminService:             logAdminService,
		LogConfigService:            logConfigService,
		IAMService:                  iamService,
		SQLAdminService:             sqlAdminService,
		CloudResourceManagerService: cloudResourceManagerService,
		MonitoringService:           monitoringService,
	}, nil
}

// WithServices is a test override function for dependency injection.
func WithServices(services *Services) OverrideFunc {
	return func(reconciler *auditLogReconciler) {
		reconciler.services = services
	}
}
