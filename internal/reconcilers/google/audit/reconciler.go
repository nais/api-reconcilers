package audit

import (
	"context"
	"fmt"

	logging "cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/logging/apiv2/loggingpb"
	"github.com/nais/api-reconcilers/internal/google_token_source"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/iterator"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/iam/v2"
	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	managedByLabelName  = "managed-by"
	managedByLabelValue = "api-reconcilers"
	reconcilerName      = "google:gcp:audit"
)

type Services struct {
	LogAdminService  *logging.Client
	LogConfigService *logging.ConfigClient
	IAMService       *iam.Service
	SQLAdminService  *sqladmin.Service
}

type logAdminReconciler struct {
	naisAuditLogProjectID    string
	services                 *Services
	tenantName               string
	workloadIdentityPoolName string
}

func (r *logAdminReconciler) Name() string {
	return reconcilerName
}

type OverrideFunc func(reconciler *logAdminReconciler)

func WithServices(services *Services) OverrideFunc {
	return func(reconciler *logAdminReconciler) {
		reconciler.services = services
	}
}

func New(ctx context.Context, serviceAccountEmail, googleManagementProjectID, tenantName string, workloadIdentityPoolName string, testOverrides ...OverrideFunc) (reconcilers.Reconciler, error) {
	// roleID := fmt.Sprintf("projects/%s/roles/cdnCacheInvalidator", naisAuditLogProjectID)
	reconciler := &logAdminReconciler{
		naisAuditLogProjectID:    googleManagementProjectID,
		tenantName:               tenantName,
		workloadIdentityPoolName: workloadIdentityPoolName,
	}

	for _, override := range testOverrides {
		override(reconciler)
	}

	if reconciler.services == nil {
		s, err := gcpServices(ctx, serviceAccountEmail)
		if err != nil {
			return nil, fmt.Errorf("get gcp services: %w", err)
		}
		reconciler.services = s
	}

	return reconciler, nil
}

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

	return &Services{
		LogAdminService:  logAdminService,
		LogConfigService: logConfigService,
		IAMService:       iamService,
		SQLAdminService:  sqlAdminService,
	}, nil
}

func (r *logAdminReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "Google Log Admin",
		Description: "Create log bucket resources for team",
		MemberAware: false,
	}
}

func (r *logAdminReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	return nil
}

func (r *logAdminReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	location := "europe-north1"
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})

	for it.Next() {
		env := it.Value()
		listSQLInstances, err := r.getSQLInstancesForTeam(ctx, naisTeam.Slug, *env.GcpProjectId)
		if err != nil {
			return fmt.Errorf("get sql instances for team %s: %w", naisTeam.Slug, err)
		}

		for _, i := range listSQLInstances {
			err := r.createLogBucketIfNotExists(ctx, env.EnvironmentName, i, location, log)
			if err != nil {
				return fmt.Errorf("create log bucket for team %s, instance %s: %w", naisTeam.Slug, i, err)
			}
		}
	}

	return it.Err()
}

func (r *logAdminReconciler) getSQLInstancesForTeam(ctx context.Context, teamSlug, teamProjectID string) ([]string, error) {
	sqlInstances := make([]string, 0)
	response, err := r.services.SQLAdminService.Instances.List(teamProjectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list sql instances for team %s: %w", teamSlug, err)
	}
	for _, i := range response.Items {
		sqlInstances = append(sqlInstances, i.Name)
	}
	return sqlInstances, nil
}

func (r *logAdminReconciler) createLogBucketIfNotExists(ctx context.Context, envName, sqlInstance, location string, log logrus.FieldLogger) error {
	parent := fmt.Sprintf("projects/%s/location/%s", r.naisAuditLogProjectID, location)
	bucketName := fmt.Sprintf("%s-%s", envName, sqlInstance)

	exists, err := r.bucketExists(ctx, fmt.Sprintf("%s/buckets/%s", parent, bucketName))
	if err != nil {
		return fmt.Errorf("check if bucket exists: %w", err)
	}

	if !exists {
		bucketReq := &loggingpb.CreateBucketRequest{
			Parent:   parent,
			BucketId: bucketName,
			Bucket: &loggingpb.LogBucket{
				RetentionDays: 1, // TODO: must be 365 when in production
				Locked:        true,
			},
		}

		bucket, err := r.services.LogConfigService.CreateBucket(ctx, bucketReq)
		if err != nil {
			return fmt.Errorf("create log bucket: %w", err)
		}
		log.Infof("Created log bucket %s", bucket.Name)
	}

	return nil
}

func (r *logAdminReconciler) bucketExists(ctx context.Context, bucketID string) (bool, error) {
	_, err := r.services.LogConfigService.GetBucket(ctx, &loggingpb.GetBucketRequest{Name: bucketID})
	if err != nil {
		s, ok := status.FromError(err)
		if ok && s.Code() == codes.NotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
