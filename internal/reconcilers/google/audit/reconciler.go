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

type logAdminReconciler struct {
	naisAuditLogProjectID    string
	services                 *Services
	tenantName               string
	workloadIdentityPoolName string
	config                   Config
}

type Config struct {
	Location      string
	RetentionDays int32
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

func New(ctx context.Context, serviceAccountEmail, naisAuditLogProjectID, tenantName string, workloadIdentityPoolName string, config Config, testOverrides ...OverrideFunc) (reconcilers.Reconciler, error) {
	// Validate required configuration
	if config.Location == "" {
		return nil, fmt.Errorf("config.Location is required")
	}

	reconciler := &logAdminReconciler{
		naisAuditLogProjectID:    naisAuditLogProjectID,
		tenantName:               tenantName,
		workloadIdentityPoolName: workloadIdentityPoolName,
		config:                   config,
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

func (r *logAdminReconciler) createLogBucketIfNotExists(ctx context.Context, teamSlug, envName, sqlInstance, location string, log logrus.FieldLogger) error {
	parent := fmt.Sprintf("projects/%s/locations/%s", r.naisAuditLogProjectID, location)
	bucketName := GenerateLogBucketName(teamSlug, envName, sqlInstance)

	// Validate bucket name according to Google Cloud Logging requirements
	if err := ValidateLogBucketName(bucketName); err != nil {
		return fmt.Errorf("invalid bucket name %q: %w", bucketName, err)
	}

	exists, err := r.bucketExists(ctx, fmt.Sprintf("%s/buckets/%s", parent, bucketName))
	if err != nil {
		return fmt.Errorf("check if bucket exists: %w", err)
	}

	if !exists {

		/*
			{"correlation_id":"e5426330-d67d-402b-b420-b4cc73e8d050","error":"create log bucket for team tommy, instance contests-test: check if bucket exists: rpc error: code = InvalidArgument desc = Name \"projects/nais-management-7178/location/europe-north1/buckets/dev-contests-test\" is missing the locations component. Expected the form projects/[PROJECT_ID]/locations/[ID]/buckets/[ID]","level":"error","msg":"error during team reconciler","reconciler":"google:gcp:audit","team":"tommy","time":"2025-10-14T13:21:04Z"}
		*/
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

// getRetentionDays returns the configured retention days with a sensible default
func (r *logAdminReconciler) getRetentionDays() int32 {
	if r.config.RetentionDays > 0 {
		return r.config.RetentionDays
	}
	// Default to 365 days for production audit logs
	return 365
}

// GenerateLogBucketName creates a bucket name from team, environment, and SQL instance components.
// Uses a hash-based approach to ensure names always fit within the 100-character limit while
// maintaining uniqueness and some readability.
func GenerateLogBucketName(teamSlug, envName, sqlInstance string) string {
	// Try the natural name first
	naturalName := fmt.Sprintf("%s-%s-%s", teamSlug, envName, sqlInstance)

	// If it fits, use it as-is
	if len(naturalName) <= 100 {
		return naturalName
	}

	// For long names, use a hybrid approach:
	// Format: {shortTeam}-{shortEnv}-{shortInstance}-{hash}
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
