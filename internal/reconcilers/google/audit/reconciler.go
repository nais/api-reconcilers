package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"

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

type auditLogReconciler struct {
	services *Services
	config   Config
}

type Config struct {
	ProjectID     string
	Location      string
	RetentionDays int32
}

func (r *auditLogReconciler) Name() string {
	return reconcilerName
}

type OverrideFunc func(reconciler *auditLogReconciler)

func WithServices(services *Services) OverrideFunc {
	return func(reconciler *auditLogReconciler) {
		reconciler.services = services
	}
}

func New(ctx context.Context, serviceAccountEmail string, config Config, testOverrides ...OverrideFunc) (reconcilers.Reconciler, error) {
	if config.ProjectID == "" {
		return nil, fmt.Errorf("audit log project ID is required: specify the GCP project ID where audit log buckets will be created")
	}
	if config.Location == "" {
		return nil, fmt.Errorf("audit log location is required: specify a GCP location (e.g., 'europe-north1', 'us-central1') where audit log buckets will be created")
	}

	reconciler := &auditLogReconciler{
		config: config,
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

func (r *auditLogReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "Google Audit Log",
		Description: "Create audit log buckets for SQL instances",
		MemberAware: false,
	}
}

func (r *auditLogReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	return nil
}

func (r *auditLogReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})

	for it.Next() {
		env := it.Value()
		listSQLInstances, err := r.getSQLInstancesForTeam(ctx, naisTeam.Slug, *env.GcpProjectId)
		if err != nil {
			return fmt.Errorf("get sql instances for team %s: %w", naisTeam.Slug, err)
		}

		for _, instance := range listSQLInstances {
			err := r.createLogBucketIfNotExists(ctx, naisTeam.Slug, env.EnvironmentName, instance, r.config.Location, log)
			if err != nil {
				return fmt.Errorf("create log bucket for team %s, instance %s: %w", naisTeam.Slug, instance, err)
			}
		}
	}

	return it.Err()
}

func (r *auditLogReconciler) getSQLInstancesForTeam(ctx context.Context, teamSlug, teamProjectID string) ([]string, error) {
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

func (r *auditLogReconciler) createLogBucketIfNotExists(ctx context.Context, teamSlug, envName, sqlInstance, location string, log logrus.FieldLogger) error {
	parent := fmt.Sprintf("projects/%s/locations/%s", r.config.ProjectID, location)
	bucketName := GenerateLogBucketName(teamSlug, envName, sqlInstance)

	if err := ValidateLogBucketName(bucketName); err != nil {
		return fmt.Errorf("invalid bucket name %q: %w", bucketName, err)
	}

	exists, err := r.bucketExists(ctx, fmt.Sprintf("%s/buckets/%s", parent, bucketName))
	if err != nil {
		return fmt.Errorf("check if bucket exists: %w", err)
	}

	if !exists {
		bucketReq := &loggingpb.CreateBucketRequest{
			Parent:   parent,
			BucketId: bucketName,
			Bucket: &loggingpb.LogBucket{
				RetentionDays: r.getRetentionDays(),
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

func (r *auditLogReconciler) bucketExists(ctx context.Context, bucketID string) (bool, error) {
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

func (r *auditLogReconciler) getRetentionDays() int32 {
	if r.config.RetentionDays > 0 {
		return r.config.RetentionDays
	}
	return 365
}

func GenerateLogBucketName(teamSlug, envName, sqlInstance string) string {
	naturalName := fmt.Sprintf("%s-%s-%s", teamSlug, envName, sqlInstance)

	if len(naturalName) <= 100 {
		return naturalName
	}

	fullIdentifier := fmt.Sprintf("%s/%s/%s", teamSlug, envName, sqlInstance)
	hash := sha256.Sum256([]byte(fullIdentifier))
	hashSuffix := fmt.Sprintf("%x", hash)[:8]

	availableForComponents := 100 - 8 - 4
	maxComponentLen := availableForComponents / 3

	shortTeam := truncateToLength(teamSlug, maxComponentLen)
	shortEnv := truncateToLength(envName, maxComponentLen)
	shortInstance := truncateToLength(sqlInstance, maxComponentLen)

	return fmt.Sprintf("%s-%s-%s-%s", shortTeam, shortEnv, shortInstance, hashSuffix)
}

func truncateToLength(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	if maxLen <= 0 {
		return ""
	}

	if maxLen <= 3 {
		return s[:maxLen]
	}

	return s[:maxLen]
}

func ValidateLogBucketName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("bucket name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("bucket name exceeds 100 character limit (got %d characters)", len(name))
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9]`).MatchString(name) {
		return fmt.Errorf("bucket name must start with an alphanumeric character")
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(name) {
		return fmt.Errorf("bucket name can only contain letters, digits, underscores, hyphens, and periods")
	}

	return nil
}
