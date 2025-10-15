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
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
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
	LogAdminService             *logging.Client
	LogConfigService            *logging.ConfigClient
	IAMService                  *iam.Service
	SQLAdminService             *sqladmin.Service
	CloudResourceManagerService *cloudresourcemanager.Service
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

	cloudResourceManagerService, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("retrieve Cloud Resource Manager service: %w", err)
	}

	return &Services{
		LogAdminService:             logAdminService,
		LogConfigService:            logConfigService,
		IAMService:                  iamService,
		SQLAdminService:             sqlAdminService,
		CloudResourceManagerService: cloudResourceManagerService,
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
		teamProjectID := env.GetGcpProjectId()
		listSQLInstances, err := r.getSQLInstancesForTeam(ctx, naisTeam.Slug, *env.GcpProjectId, log)
		if err != nil {
			return fmt.Errorf("get sql instances for team %s: %w", naisTeam.Slug, err)
		}

		for _, instance := range listSQLInstances {
			bucketName, err := r.createLogBucketIfNotExists(ctx, naisTeam.Slug, env.EnvironmentName, instance, r.config.Location, log)
			if err != nil {
				return fmt.Errorf("create log bucket for team %s, instance %s: %w", naisTeam.Slug, instance, err)
			}

			_, writerIdentity, err := r.createLogSinkIfNotExists(ctx, teamProjectID, naisTeam.Slug, env.EnvironmentName, instance, bucketName, log)
			if err != nil {
				return fmt.Errorf("create log sink for team %s, instance %s: %w", naisTeam.Slug, instance, err)
			}

			if writerIdentity != "" {
				log.Debugf("Granting bucket write permission for sink writer identity: %s", writerIdentity)
				err = r.grantBucketWritePermission(ctx, bucketName, writerIdentity, log)
				if err != nil {
					return fmt.Errorf("grant bucket write permission for team %s, instance %s: %w", naisTeam.Slug, instance, err)
				}
			} else {
				log.Debugf("No writer identity found for sink, skipping permission grant")
			}
		}
	}

	return it.Err()
}

func (r *auditLogReconciler) getSQLInstancesForTeam(ctx context.Context, teamSlug, teamProjectID string, log logrus.FieldLogger) ([]string, error) {
	sqlInstances := make([]string, 0)
	response, err := r.services.SQLAdminService.Instances.List(teamProjectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list sql instances for team %s: %w", teamSlug, err)
	}
	for _, i := range response.Items {
		if HasPgAuditEnabled(i) {
			sqlInstances = append(sqlInstances, i.Name)
		}
	}
	return sqlInstances, nil
}

func HasPgAuditEnabled(instance *sqladmin.DatabaseInstance) bool {
	if instance.Settings == nil || instance.Settings.DatabaseFlags == nil {
		return false
	}

	for _, flag := range instance.Settings.DatabaseFlags {
		if flag.Name == "cloudsql.enable_pgaudit" && flag.Value == "on" {
			return true
		}
	}
	return false
}

func (r *auditLogReconciler) createLogBucketIfNotExists(ctx context.Context, teamSlug, envName, sqlInstance, location string, log logrus.FieldLogger) (string, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s", r.config.ProjectID, location)
	bucketName := GenerateLogBucketName(teamSlug, envName, sqlInstance)

	if err := ValidateLogBucketName(bucketName); err != nil {
		return "", fmt.Errorf("invalid bucket name %q: %w", bucketName, err)
	}

	exists, err := r.bucketExists(ctx, fmt.Sprintf("%s/buckets/%s", parent, bucketName))
	if err != nil {
		return "", fmt.Errorf("check if bucket exists: %w", err)
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
			return "", fmt.Errorf("create log bucket: %w", err)
		}
		log.Infof("Created log bucket %s", bucket.Name)
	} else {
		log.Debugf("Log bucket %s already exists, skipping", bucketName)
	}

	return bucketName, nil
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
	return 90
}

func (r *auditLogReconciler) createLogSinkIfNotExists(ctx context.Context, teamProjectID, teamSlug, envName, sqlInstance, bucketName string, log logrus.FieldLogger) (string, string, error) {
	parent := fmt.Sprintf("projects/%s", teamProjectID)
	sinkName := GenerateLogSinkName(teamSlug, envName, sqlInstance)
	destination := fmt.Sprintf("logging.googleapis.com/projects/%s/locations/%s/buckets/%s", r.config.ProjectID, r.config.Location, bucketName)

	// Get application users for this SQL instance
	appUser, err := r.getApplicationUser(ctx, teamProjectID, sqlInstance, log)
	if err != nil {
		return "", "", fmt.Errorf("get application users for instance %s: %w", sqlInstance, err)
	}

	// Build the filter with exclusions for application users
	filter := r.BuildLogFilter(teamProjectID, sqlInstance, appUser)

	if err := ValidateLogSinkName(sinkName); err != nil {
		return "", "", fmt.Errorf("invalid sink name %q: %w", sinkName, err)
	}

	exists, err := r.sinkExists(ctx, fmt.Sprintf("%s/sinks/%s", parent, sinkName))
	if err != nil {
		return "", "", fmt.Errorf("check if sink exists: %w", err)
	}

	var writerIdentity string
	if !exists {
		sinkReq := &loggingpb.CreateSinkRequest{
			Parent:               parent,
			UniqueWriterIdentity: true, // Required for cross-project exports
			Sink: &loggingpb.LogSink{
				Name:        sinkName,
				Destination: destination,
				Filter:      filter,
				Description: fmt.Sprintf("Audit logs for SQL instance %s in team %s environment %s", sqlInstance, teamSlug, envName),
			},
		}

		sink, err := r.services.LogConfigService.CreateSink(ctx, sinkReq)
		if err != nil {
			return "", "", fmt.Errorf("create log sink: %w", err)
		}
		log.Infof("Created log sink %s -> %s", sink.Name, destination)
		writerIdentity = sink.WriterIdentity
	} else {
		log.Debugf("Log sink %s already exists, skipping", sinkName)
		// For existing sinks, we need to get the writer identity by retrieving the sink
		existingSink, err := r.services.LogConfigService.GetSink(ctx, &loggingpb.GetSinkRequest{
			SinkName: fmt.Sprintf("%s/sinks/%s", parent, sinkName),
		})
		if err != nil {
			return "", "", fmt.Errorf("get existing sink writer identity: %w", err)
		}
		writerIdentity = existingSink.WriterIdentity
	}

	return sinkName, writerIdentity, nil
}

func (r *auditLogReconciler) grantBucketWritePermission(ctx context.Context, bucketName, writerIdentity string, log logrus.FieldLogger) error {
	// For log buckets, we need to grant the "roles/logging.bucketWriter" role to the sink's writer identity
	// Use Cloud Resource Manager API to manage IAM policies on the project level

	// Get current IAM policy for the project
	policy, err := r.services.CloudResourceManagerService.Projects.GetIamPolicy(r.config.ProjectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("get project IAM policy: %w", err)
	}

	// Check if the writer identity already has the required role
	bucketWriterRole := "roles/logging.bucketWriter"
	hasPermission := false

	for _, binding := range policy.Bindings {
		if binding.Role == bucketWriterRole {
			for _, member := range binding.Members {
				if member == writerIdentity {
					hasPermission = true
					break
				}
			}
			if !hasPermission {
				// Add the writer identity to existing binding
				binding.Members = append(binding.Members, writerIdentity)
				hasPermission = true
			}
			break
		}
	}

	// If no existing binding for the role, create a new one
	if !hasPermission {
		newBinding := &cloudresourcemanager.Binding{
			Role:    bucketWriterRole,
			Members: []string{writerIdentity},
		}
		policy.Bindings = append(policy.Bindings, newBinding)
	}

	// Update the IAM policy
	setRequest := &cloudresourcemanager.SetIamPolicyRequest{
		Policy: policy,
	}

	_, err = r.services.CloudResourceManagerService.Projects.SetIamPolicy(r.config.ProjectID, setRequest).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("set project IAM policy: %w", err)
	}

	log.Infof("Granted %s permission to writer identity %s for bucket %s", bucketWriterRole, writerIdentity, bucketName)
	return nil
}

func (r *auditLogReconciler) sinkExists(ctx context.Context, sinkID string) (bool, error) {
	_, err := r.services.LogConfigService.GetSink(ctx, &loggingpb.GetSinkRequest{SinkName: sinkID})
	if err != nil {
		s, ok := status.FromError(err)
		if ok && s.Code() == codes.NotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (r *auditLogReconciler) getApplicationUser(ctx context.Context, teamProjectID, sqlInstance string, log logrus.FieldLogger) (string, error) {
	// Get the SQL instance details to extract the application user from labels
	instance, err := r.services.SQLAdminService.Instances.Get(teamProjectID, sqlInstance).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("get SQL instance %s: %w", sqlInstance, err)
	}

	// Check for "app" label which contains the application user name
	if instance.Settings != nil && instance.Settings.UserLabels != nil {
		if appUser, exists := instance.Settings.UserLabels["app"]; exists && appUser != "" {
			log.Debugf("Found application user from 'app' label for SQL instance %s: %s", sqlInstance, appUser)
			return appUser, nil
		}
	}
	log.Warningf("No 'app' found for label for SQL instance %s", sqlInstance)
	return "", nil
}

func (r *auditLogReconciler) BuildLogFilter(teamProjectID, sqlInstance string, appUser string) string {
	// Base filter for Cloud SQL audit logs
	baseFilter := fmt.Sprintf(`resource.type="cloudsql_database"
AND resource.labels.database_id="%s:%s"
AND logName="projects/%s/logs/cloudaudit.googleapis.com%%2Fdata_access"
AND protoPayload.request.@type="type.googleapis.com/google.cloud.sql.audit.v1.PgAuditEntry"
AND NOT protoPayload.request.user="%s"`,
		teamProjectID, sqlInstance, teamProjectID, appUser)

	return baseFilter
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

func GenerateLogSinkName(teamSlug, envName, sqlInstance string) string {
	// Similar to bucket name generation but with "sink-" prefix
	naturalName := fmt.Sprintf("sink-%s-%s-%s", teamSlug, envName, sqlInstance)

	// Log sink names have a 100 character limit like buckets
	if len(naturalName) <= 100 {
		return naturalName
	}

	fullIdentifier := fmt.Sprintf("%s/%s/%s", teamSlug, envName, sqlInstance)
	hash := sha256.Sum256([]byte(fullIdentifier))
	hashSuffix := fmt.Sprintf("%x", hash)[:8]

	// Account for "sink-" prefix (5 chars), hash suffix (8 chars), and separators (4 chars)
	availableForComponents := 100 - 5 - 8 - 4
	maxComponentLen := availableForComponents / 3

	shortTeam := truncateToLength(teamSlug, maxComponentLen)
	shortEnv := truncateToLength(envName, maxComponentLen)
	shortInstance := truncateToLength(sqlInstance, maxComponentLen)

	return fmt.Sprintf("sink-%s-%s-%s-%s", shortTeam, shortEnv, shortInstance, hashSuffix)
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

func ValidateLogSinkName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("sink name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("sink name exceeds 100 character limit (got %d characters)", len(name))
	}

	// Log sink names must start with a letter or underscore
	if !regexp.MustCompile(`^[a-zA-Z_]`).MatchString(name) {
		return fmt.Errorf("sink name must start with a letter or underscore")
	}

	// Log sink names can contain letters, digits, underscores, and hyphens
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(name) {
		return fmt.Errorf("sink name can only contain letters, digits, underscores, and hyphens")
	}

	return nil
}
