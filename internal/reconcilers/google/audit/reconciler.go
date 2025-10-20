package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

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
	monitoring "google.golang.org/api/monitoring/v3"
	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

const (
	reconcilerName = "google:gcp:audit"

	configRetentionDays        = "audit:retention_days"
	configLocked               = "audit:locked"
	configNotificationChannels = "audit:notification_channels"
)

type Services struct {
	LogAdminService             *logging.Client
	LogConfigService            *logging.ConfigClient
	IAMService                  *iam.Service
	SQLAdminService             *sqladmin.Service
	CloudResourceManagerService *cloudresourcemanager.Service
	MonitoringService           *monitoring.Service
}

type auditLogReconciler struct {
	services *Services
	config   Config
}

type Config struct {
	ProjectID string
	Location  string
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

func (r *auditLogReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "Google Audit Log",
		Description: "Create audit log buckets for SQL instances",
		MemberAware: false,
		Config: []*protoapi.ReconcilerConfigSpec{
			{
				Key:         configRetentionDays,
				DisplayName: "Retention Days",
				Description: "The number of days to retain audit logs. Must be a positive integer greater than 0. Examples: 30, 90, 365. Can only be modified if bucket is not locked.",
				Secret:      false,
			},
			{
				Key:         configLocked,
				DisplayName: "Lock Buckets",
				Description: "Set to true for immutable log buckets for auditing purposes. Not possible to revert once set to true. False if not specified.",
				Secret:      false,
			},
			{
				Key:         configNotificationChannels,
				DisplayName: "Notification Channels",
				Description: "Comma-separated list of notification channel resource names for creating or updating alert policies. Format: projects/TEAM_PROJECT_ID/notificationChannels/CHANNEL_ID. Multiple channels separated by commas.",
				Secret:      false,
			},
		},
	}
}

func (r *auditLogReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})

	for it.Next() {
		env := it.Value()
		teamProjectID := env.GetGcpProjectId()

		// Since SQL instances may already be deleted when a team is deleted,
		// we need to find all existing sinks for this team/environment
		// instead of relying on the existence of SQL instances
		err := r.deleteAllTeamSinks(ctx, teamProjectID, naisTeam.Slug, env.EnvironmentName, log)
		if err != nil {
			log.WithError(err).Warn("Failed to delete all team sinks")
			// Continue with other environments instead of failing completely
		}
	}

	return it.Err()
}

// deleteAllTeamSinks finds and deletes all sinks created by this reconciler for a specific team/environment
func (r *auditLogReconciler) deleteAllTeamSinks(ctx context.Context, teamProjectID, teamSlug, envName string, log logrus.FieldLogger) error {
	// Check if we have a valid logging service
	if r.services == nil || r.services.LogConfigService == nil {
		log.Warn("No logging service available, cannot list or delete sinks")
		return nil // Return nil to not fail the overall deletion process
	}

	// List all sinks in the project
	parent := fmt.Sprintf("projects/%s", teamProjectID)
	req := &loggingpb.ListSinksRequest{
		Parent: parent,
	}

	it := r.services.LogConfigService.ListSinks(ctx, req)

	for {
		sink, err := it.Next()
		if err != nil {
			if err.Error() == "no more items in iterator" {
				break
			}
			return fmt.Errorf("failed to iterate sinks: %w", err)
		}

		// Check if this sink was created by our reconciler for this team/environment
		if r.isManagedSink(sink, teamSlug, envName) {
			log.WithField("sink", sink.Name).Info("Found managed sink for deletion")

			// Get the sink's writer identity before deleting it
			writerIdentity := sink.WriterIdentity

			// Extract bucket name from destination to remove IAM permissions
			bucketName := r.extractBucketNameFromDestination(sink.Destination)

			// Delete the log sink
			err = r.deleteSink(ctx, teamProjectID, sink.Name, log)
			if err != nil {
				log.WithError(err).WithField("sink", sink.Name).Error("Failed to delete log sink")
				// Continue with other sinks instead of failing completely
				continue
			}

			// Remove IAM permissions from bucket if we have a writer identity and bucket name
			if writerIdentity != "" && bucketName != "" {
				err = r.removeBucketWritePermission(ctx, bucketName, writerIdentity, log)
				if err != nil {
					log.WithError(err).WithField("bucket", bucketName).WithField("identity", writerIdentity).Warn("Failed to remove bucket write permission")
					// Continue with other permissions instead of failing completely
				}
			}
		}
	}

	return nil
}

func (r *auditLogReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})

	for it.Next() {
		env := it.Value()
		teamProjectID := env.GetGcpProjectId()

		// Get SQL instances for this team/environment
		listSQLInstances, err := r.getSQLInstancesForTeam(ctx, naisTeam.Slug, *env.GcpProjectId, log)
		if err != nil {
			return fmt.Errorf("get sql instances for team %s: %w", naisTeam.Slug, err)
		}

		// Skip if no SQL instances with pgaudit enabled
		if len(listSQLInstances) == 0 {
			log.Debugf("No SQL instances with pgaudit enabled found for team %s environment %s", naisTeam.Slug, env.EnvironmentName)
			continue
		}

		// Create one log bucket per team environment (shared by all SQL instances)
		bucketName, err := r.createOrUpdateLogBucketIfNeeded(ctx, client, naisTeam.Slug, env.EnvironmentName, r.config.Location, log)
		if err != nil {
			return fmt.Errorf("create or update log bucket for team %s environment %s: %w", naisTeam.Slug, env.EnvironmentName, err)
		}

		// Collect application users from all SQL instances
		var appUsers []string
		for _, instance := range listSQLInstances {
			appUser, err := r.getApplicationUser(ctx, teamProjectID, instance, log)
			if err != nil {
				log.WithError(err).Warnf("Failed to get application user for instance %s, continuing", instance)
				continue
			}
			if appUser != "" {
				appUsers = append(appUsers, appUser)
			}
		}

		// Create one log sink per team environment covering all SQL instances
		sinkName, writerIdentity, err := r.createOrUpdateLogSinkIfNeeded(ctx, teamProjectID, naisTeam.Slug, env.EnvironmentName, bucketName, appUsers, log)
		if err != nil {
			return fmt.Errorf("create or update log sink for team %s environment %s: %w", naisTeam.Slug, env.EnvironmentName, err)
		}

		// Create log alert for sink change monitoring
		if err := r.createSinkChangeAlert(ctx, client, teamProjectID, naisTeam.Slug, env.EnvironmentName, sinkName, log); err != nil {
			return fmt.Errorf("create sink change alert for team %s environment %s: %w", naisTeam.Slug, env.EnvironmentName, err)
		}

		if writerIdentity != "" {
			log.Debugf("Granting bucket write permission for sink writer identity: %s", writerIdentity)
			err = r.grantBucketWritePermission(ctx, bucketName, writerIdentity, log)
			if err != nil {
				return fmt.Errorf("grant bucket write permission for team %s environment %s: %w", naisTeam.Slug, env.EnvironmentName, err)
			}
		} else {
			log.Debugf("No writer identity found for sink, skipping permission grant")
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

// HasPgAuditEnabled checks if a SQL instance has the pgaudit flag enabled
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

func (r *auditLogReconciler) createOrUpdateLogBucketIfNeeded(ctx context.Context, client *apiclient.APIClient, teamSlug, envName, location string, log logrus.FieldLogger) (string, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s", r.config.ProjectID, location)
	bucketName := GenerateLogBucketName(teamSlug, envName)

	if err := ValidateLogBucketName(bucketName); err != nil {
		return "", fmt.Errorf("invalid bucket name %q: %w", bucketName, err)
	}

	bucketPath := fmt.Sprintf("%s/buckets/%s", parent, bucketName)
	exists, err := r.bucketExists(ctx, bucketPath)
	if err != nil {
		return "", fmt.Errorf("check if bucket exists: %w", err)
	}

	// Get current configuration values
	retentionDays, err := r.getRetentionDays(ctx, client)
	if err != nil {
		return "", fmt.Errorf("get retention days: %w", err)
	}

	locked, err := r.getBucketLocked(ctx, client)
	if err != nil {
		return "", fmt.Errorf("get bucket locked: %w", err)
	}

	if !exists {
		// Create new bucket
		bucketReq := &loggingpb.CreateBucketRequest{
			Parent:   parent,
			BucketId: bucketName,
			Bucket: &loggingpb.LogBucket{
				Description:   fmt.Sprintf("Audit log bucket for team %s environment %s (created by api-reconcilers)", teamSlug, envName),
				RetentionDays: retentionDays,
				Locked:        locked,
			},
		}

		bucket, err := r.services.LogConfigService.CreateBucket(ctx, bucketReq)
		if err != nil {
			return "", fmt.Errorf("create log bucket: %w", err)
		}
		log.Infof("Created log bucket %s for team %s environment %s", bucket.Name, teamSlug, envName)
	} else {
		// Check if existing bucket needs updates
		existingBucket, err := r.services.LogConfigService.GetBucket(ctx, &loggingpb.GetBucketRequest{Name: bucketPath})
		if err != nil {
			return "", fmt.Errorf("get existing bucket: %w", err)
		}

		needsUpdate := false
		updateMask := []string{}

		// Check if retention days need updating (only if bucket is not locked)
		if !existingBucket.Locked && existingBucket.RetentionDays != retentionDays {
			needsUpdate = true
			updateMask = append(updateMask, "retention_days")
			log.Debugf("Bucket %s retention days will be updated from %d to %d", bucketName, existingBucket.RetentionDays, retentionDays)
		} else if existingBucket.Locked && existingBucket.RetentionDays != retentionDays {
			log.Warnf("Bucket %s is locked, cannot update retention days from %d to %d", bucketName, existingBucket.RetentionDays, retentionDays)
		}

		// Check if locked status needs updating (can only go from false to true)
		if !existingBucket.Locked && locked {
			needsUpdate = true
			updateMask = append(updateMask, "locked")
			log.Debugf("Bucket %s will be locked", bucketName)
		} else if existingBucket.Locked && !locked {
			log.Warnf("Bucket %s is already locked, cannot unlock it", bucketName)
		}

		if needsUpdate {
			// Update the bucket
			updateReq := &loggingpb.UpdateBucketRequest{
				Name: bucketPath,
				Bucket: &loggingpb.LogBucket{
					Name:          existingBucket.Name,
					Description:   existingBucket.Description,
					RetentionDays: retentionDays,
					Locked:        locked,
				},
				UpdateMask: &fieldmaskpb.FieldMask{
					Paths: updateMask,
				},
			}

			updatedBucket, err := r.services.LogConfigService.UpdateBucket(ctx, updateReq)
			if err != nil {
				return "", fmt.Errorf("update log bucket: %w", err)
			}
			log.Infof("Updated log bucket %s for team %s environment %s", updatedBucket.Name, teamSlug, envName)
		} else {
			log.Debugf("Log bucket %s already exists with correct configuration, skipping", bucketName)
		}
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

func (r *auditLogReconciler) getRetentionDays(ctx context.Context, client *apiclient.APIClient) (int32, error) {
	config, err := client.Reconcilers().Config(ctx, &protoapi.ConfigReconcilerRequest{
		ReconcilerName: r.Name(),
	})
	if err != nil {
		return 0, fmt.Errorf("get reconciler config: %w", err)
	}

	for _, c := range config.Nodes {
		if c.Key == configRetentionDays {
			if c.Value == "" {
				return 0, fmt.Errorf("retention days config value is empty: %s must be configured", configRetentionDays)
			}

			// Parse the value as an integer
			var retentionDays int32
			if _, err := fmt.Sscanf(c.Value, "%d", &retentionDays); err != nil {
				return 0, fmt.Errorf("invalid retention days value %q: %w", c.Value, err)
			}

			if retentionDays <= 0 {
				return 0, fmt.Errorf("retention days must be greater than 0, got %d", retentionDays)
			}

			return retentionDays, nil
		}
	}

	return 0, fmt.Errorf("retention days config not found: %s must be configured", configRetentionDays)
}

func (r *auditLogReconciler) getBucketLocked(ctx context.Context, client *apiclient.APIClient) (bool, error) {
	config, err := client.Reconcilers().Config(ctx, &protoapi.ConfigReconcilerRequest{
		ReconcilerName: r.Name(),
	})
	if err != nil {
		return false, fmt.Errorf("get reconciler config: %w", err)
	}

	for _, c := range config.Nodes {
		if c.Key == configLocked {
			if c.Value == "" {
				// Default to false if not configured
				return false, nil
			}

			// Parse the value as a boolean
			switch strings.ToLower(c.Value) {
			case "true", "1", "yes", "on":
				return true, nil
			case "false", "0", "no", "off":
				return false, nil
			default:
				return false, fmt.Errorf("invalid locked value %q: must be true/false", c.Value)
			}
		}
	}

	// Default to false if config not found
	return false, nil
}

func (r *auditLogReconciler) getNotificationChannels(ctx context.Context, client *apiclient.APIClient) ([]string, error) {
	config, err := client.Reconcilers().Config(ctx, &protoapi.ConfigReconcilerRequest{
		ReconcilerName: r.Name(),
	})
	if err != nil {
		return nil, fmt.Errorf("get reconciler config: %w", err)
	}

	for _, c := range config.Nodes {
		if c.Key == configNotificationChannels {
			if c.Value == "" {
				// Default to empty list if not configured
				return []string{}, nil
			}

			// Split by comma and trim whitespace
			channels := strings.Split(c.Value, ",")
			var trimmedChannels []string
			for _, channel := range channels {
				trimmed := strings.TrimSpace(channel)
				if trimmed != "" {
					trimmedChannels = append(trimmedChannels, trimmed)
				}
			}
			return trimmedChannels, nil
		}
	}

	// Default to empty list if config not found
	return []string{}, nil
}

func (r *auditLogReconciler) createOrUpdateLogSinkIfNeeded(ctx context.Context, teamProjectID, teamSlug, envName, bucketName string, appUsers []string, log logrus.FieldLogger) (string, string, error) {
	parent := fmt.Sprintf("projects/%s", teamProjectID)
	sinkName := GenerateLogSinkName(teamSlug, envName)
	destination := fmt.Sprintf("logging.googleapis.com/projects/%s/locations/%s/buckets/%s", r.config.ProjectID, r.config.Location, bucketName)

	filter := r.BuildLogFilter(teamProjectID, appUsers)

	if err := ValidateLogSinkName(sinkName); err != nil {
		return "", "", fmt.Errorf("invalid sink name %q: %w", sinkName, err)
	}

	sinkPath := fmt.Sprintf("%s/sinks/%s", parent, sinkName)
	exists, err := r.sinkExists(ctx, sinkPath)
	if err != nil {
		return "", "", fmt.Errorf("check if sink exists: %w", err)
	}

	var writerIdentity string
	if !exists {
		// Create new sink
		sinkReq := &loggingpb.CreateSinkRequest{
			Parent:               parent,
			UniqueWriterIdentity: true,
			Sink: &loggingpb.LogSink{
				Name:        sinkName,
				Destination: destination,
				Filter:      filter,
				Description: fmt.Sprintf("Audit log sink for team %s environment %s (created by api-reconcilers)", teamSlug, envName),
			},
		}

		sink, err := r.services.LogConfigService.CreateSink(ctx, sinkReq)
		if err != nil {
			return "", "", fmt.Errorf("create log sink: %w", err)
		}
		log.Infof("Created log sink %s -> %s", sink.Name, destination)
		writerIdentity = sink.WriterIdentity
	} else {
		// Check if existing sink needs updates
		existingSink, err := r.services.LogConfigService.GetSink(ctx, &loggingpb.GetSinkRequest{
			SinkName: sinkPath,
		})
		if err != nil {
			return "", "", fmt.Errorf("get existing sink: %w", err)
		}

		needsUpdate := false
		updateMask := []string{}

		// Check if filter needs updating
		if existingSink.Filter != filter {
			needsUpdate = true
			updateMask = append(updateMask, "filter")
			log.Debugf("Sink %s filter will be updated", sinkName)
		}

		// Check if destination needs updating (less common but possible)
		if existingSink.Destination != destination {
			needsUpdate = true
			updateMask = append(updateMask, "destination")
			log.Debugf("Sink %s destination will be updated from %s to %s", sinkName, existingSink.Destination, destination)
		}

		if needsUpdate {
			// Update the sink
			updateReq := &loggingpb.UpdateSinkRequest{
				SinkName: sinkPath,
				Sink: &loggingpb.LogSink{
					Name:        existingSink.Name,
					Destination: destination,
					Filter:      filter,
					Description: existingSink.Description,
				},
				UpdateMask: &fieldmaskpb.FieldMask{
					Paths: updateMask,
				},
			}

			updatedSink, err := r.services.LogConfigService.UpdateSink(ctx, updateReq)
			if err != nil {
				return "", "", fmt.Errorf("update log sink: %w", err)
			}
			log.Infof("Updated log sink %s for team %s environment %s", updatedSink.Name, teamSlug, envName)
			writerIdentity = updatedSink.WriterIdentity
		} else {
			log.Debugf("Log sink %s already exists with correct configuration, skipping", sinkName)
			writerIdentity = existingSink.WriterIdentity
		}
	}

	return sinkName, writerIdentity, nil
}

// grantBucketWritePermission grants the logging.bucketWriter role to the sink's writer identity
func (r *auditLogReconciler) grantBucketWritePermission(ctx context.Context, bucketName, writerIdentity string, log logrus.FieldLogger) error {
	policy, err := r.services.CloudResourceManagerService.Projects.GetIamPolicy(r.config.ProjectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("get project IAM policy: %w", err)
	}

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
			break
		}
	}

	if hasPermission {
		log.Debugf("Writer identity %s already has %s permission, skipping grant", writerIdentity, bucketWriterRole)
		return nil
	}

	for _, binding := range policy.Bindings {
		if binding.Role == bucketWriterRole {
			binding.Members = append(binding.Members, writerIdentity)
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		newBinding := &cloudresourcemanager.Binding{
			Role:    bucketWriterRole,
			Members: []string{writerIdentity},
		}
		policy.Bindings = append(policy.Bindings, newBinding)
	}

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

// getApplicationUser extracts the application user from SQL instance labels
func (r *auditLogReconciler) getApplicationUser(ctx context.Context, teamProjectID, sqlInstance string, log logrus.FieldLogger) (string, error) {
	instance, err := r.services.SQLAdminService.Instances.Get(teamProjectID, sqlInstance).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("get SQL instance %s: %w", sqlInstance, err)
	}

	if instance.Settings != nil && instance.Settings.UserLabels != nil {
		if appUser, exists := instance.Settings.UserLabels["app"]; exists && appUser != "" {
			log.Debugf("Found application user from 'app' label for SQL instance %s: %s", sqlInstance, appUser)
			return appUser, nil
		}
	}
	log.Warningf("No 'app' found for label for SQL instance %s", sqlInstance)
	return "", nil
}

// BuildLogFilter constructs a Cloud SQL audit log filter for all SQL instances in the project
func (r *auditLogReconciler) BuildLogFilter(teamProjectID string, appUsers []string) string {
	baseFilter := fmt.Sprintf(`resource.type="cloudsql_database"
AND logName="projects/%s/logs/cloudaudit.googleapis.com%%2Fdata_access"
AND protoPayload.request.@type="type.googleapis.com/google.cloud.sql.audit.v1.PgAuditEntry"`, teamProjectID)

	// Exclude application users if any are specified
	for _, appUser := range appUsers {
		if appUser != "" {
			baseFilter += fmt.Sprintf(`
AND NOT protoPayload.request.user="%s"`, appUser)
		}
	}

	return baseFilter
}

// GenerateLogBucketName generates a unique bucket name with hash collision resistance
// Creates one bucket per team environment (not per SQL instance)
func GenerateLogBucketName(teamSlug, envName string) string {
	naturalName := fmt.Sprintf("%s-%s", teamSlug, envName)

	if len(naturalName) <= 100 {
		return naturalName
	}

	fullIdentifier := fmt.Sprintf("%s/%s", teamSlug, envName)
	hash := sha256.Sum256([]byte(fullIdentifier))
	hashSuffix := fmt.Sprintf("%x", hash)[:8]

	availableForComponents := 100 - 8 - 1 // 1 for separator
	maxComponentLen := availableForComponents / 2

	shortTeam := truncateToLength(teamSlug, maxComponentLen)
	shortEnv := truncateToLength(envName, maxComponentLen)

	return fmt.Sprintf("%s-%s-%s", shortTeam, shortEnv, hashSuffix)
}

// truncateToLength truncates a string to the specified maximum length
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

// GenerateLogSinkName generates a unique sink name with hash collision resistance
// Creates one sink per team environment (not per SQL instance)
func GenerateLogSinkName(teamSlug, envName string) string {
	naturalName := fmt.Sprintf("sql-audit-sink-%s-%s", teamSlug, envName)

	if len(naturalName) <= 100 {
		return naturalName
	}

	fullIdentifier := fmt.Sprintf("%s/%s", teamSlug, envName)
	hash := sha256.Sum256([]byte(fullIdentifier))
	hashSuffix := fmt.Sprintf("%x", hash)[:8]

	availableForComponents := 100 - 15 - 8 - 2 // 15 for "sql-audit-sink-", 8 for hash, 2 for separators
	maxComponentLen := availableForComponents / 2

	shortTeam := truncateToLength(teamSlug, maxComponentLen)
	shortEnv := truncateToLength(envName, maxComponentLen)

	return fmt.Sprintf("sql-audit-sink-%s-%s-%s", shortTeam, shortEnv, hashSuffix)
}

// ValidateLogBucketName validates a log bucket name against Google Cloud naming rules
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

// ValidateLogSinkName validates a log sink name against Google Cloud naming rules
func ValidateLogSinkName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("sink name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("sink name exceeds 100 character limit (got %d characters)", len(name))
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9]`).MatchString(name) {
		return fmt.Errorf("sink name must start with an alphanumeric character")
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(name) {
		return fmt.Errorf("sink name can only contain letters, digits, underscores, hyphens, and periods")
	}

	return nil
}

// deleteSink removes a log sink
func (r *auditLogReconciler) deleteSink(ctx context.Context, teamProjectID, sinkName string, log logrus.FieldLogger) error {
	parent := fmt.Sprintf("projects/%s", teamProjectID)
	sinkPath := fmt.Sprintf("%s/sinks/%s", parent, sinkName)

	req := &loggingpb.DeleteSinkRequest{
		SinkName: sinkPath,
	}

	err := r.services.LogConfigService.DeleteSink(ctx, req)
	if err != nil {
		// Check if the sink was already deleted
		if status.Code(err) == codes.NotFound {
			log.WithField("sink", sinkName).Debug("Sink already deleted")
			return nil
		}
		return fmt.Errorf("delete sink %s: %w", sinkName, err)
	}

	log.WithField("sink", sinkName).Info("Successfully deleted log sink")
	return nil
}

// removeBucketWritePermission removes write permission for a service account from a bucket
func (r *auditLogReconciler) removeBucketWritePermission(ctx context.Context, bucketName, writerIdentity string, log logrus.FieldLogger) error {
	// Get current project IAM policy
	policy, err := r.services.CloudResourceManagerService.Projects.GetIamPolicy(r.config.ProjectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("get project IAM policy: %w", err)
	}

	// Remove the member from logging.bucketWriter role
	role := "roles/logging.bucketWriter"
	modified := false

	for _, binding := range policy.Bindings {
		if binding.Role == role {
			// Filter out the writer identity
			var newMembers []string
			for _, member := range binding.Members {
				if member != writerIdentity {
					newMembers = append(newMembers, member)
				} else {
					modified = true
					log.WithFields(logrus.Fields{
						"bucket":   bucketName,
						"identity": writerIdentity,
						"role":     role,
					}).Info("Removing bucket write permission")
				}
			}
			binding.Members = newMembers
			break
		}
	}

	if !modified {
		log.WithField("identity", writerIdentity).Debug("Writer identity not found in bucket permissions")
		return nil
	}

	// Set the updated policy
	_, err = r.services.CloudResourceManagerService.Projects.SetIamPolicy(r.config.ProjectID, &cloudresourcemanager.SetIamPolicyRequest{
		Policy: policy,
	}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("set project IAM policy: %w", err)
	}

	log.WithFields(logrus.Fields{
		"bucket":   bucketName,
		"identity": writerIdentity,
		"role":     role,
	}).Info("Successfully removed bucket write permission")

	return nil
}

// isManagedSink checks if a sink was created by this reconciler for the given team and environment
func (r *auditLogReconciler) isManagedSink(sink *loggingpb.LogSink, teamSlug, envName string) bool {
	// Check if the sink name follows our naming convention (sql-audit-sink-<team>-<env>)
	expectedName := fmt.Sprintf("sql-audit-sink-%s-%s", teamSlug, envName)

	// For exact match
	if sink.Name == expectedName {
		return true
	}

	// For hash-based names, check if it matches the pattern sql-audit-sink-<team>-<env>-<hash>
	expectedPrefixWithHash := fmt.Sprintf("sql-audit-sink-%s-%s-", teamSlug, envName)
	if strings.HasPrefix(sink.Name, expectedPrefixWithHash) && len(sink.Name) > len(expectedPrefixWithHash) {
		return true
	}

	return false
}

// extractBucketNameFromDestination extracts the bucket name from a log sink destination
func (r *auditLogReconciler) extractBucketNameFromDestination(destination string) string {
	// Expected format: logging.googleapis.com/projects/PROJECT/locations/LOCATION/buckets/BUCKET
	pattern := fmt.Sprintf(`logging\.googleapis\.com/projects/%s/locations/%s/buckets/(.+)`,
		regexp.QuoteMeta(r.config.ProjectID), regexp.QuoteMeta(r.config.Location))

	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(destination)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// createSinkChangeAlert creates a log-based metric and alert to monitor for changes to the specified sink
func (r *auditLogReconciler) createSinkChangeAlert(ctx context.Context, client *apiclient.APIClient, teamProjectID, teamSlug, envName, sinkName string, log logrus.FieldLogger) error {
	// Create an alert policy based on log matching (no metric needed)
	alertPolicyName := r.generateAlertPolicyName(teamSlug, envName)
	if err := r.createOrUpdateAlertPolicyIfNeeded(ctx, client, teamProjectID, alertPolicyName, teamSlug, envName, sinkName, log); err != nil {
		return fmt.Errorf("create or update alert policy: %w", err)
	}

	return nil
}

// createOrUpdateAlertPolicyIfNeeded creates an alert policy for log matching or updates it if needed
func (r *auditLogReconciler) createOrUpdateAlertPolicyIfNeeded(ctx context.Context, client *apiclient.APIClient, teamProjectID, alertPolicyName, teamSlug, envName, sinkName string, log logrus.FieldLogger) error {
	parent := fmt.Sprintf("projects/%s", teamProjectID)

	// Check if alert policy already exists
	listCall := r.services.MonitoringService.Projects.AlertPolicies.List(parent)
	existingPolicies, err := listCall.Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("list existing alert policies: %w", err)
	}

	// Get notification channels configuration
	notificationChannels, err := r.getNotificationChannels(ctx, client)
	if err != nil {
		return fmt.Errorf("get notification channels: %w", err)
	}

	// Check if our alert policy already exists
	var existingPolicy *monitoring.AlertPolicy
	for _, policy := range existingPolicies.AlertPolicies {
		if policy.DisplayName == alertPolicyName {
			existingPolicy = policy
			break
		}
	}

	// Create the alert policy structure
	alertPolicy := &monitoring.AlertPolicy{
		DisplayName: alertPolicyName,
		Documentation: &monitoring.Documentation{
			Content:  fmt.Sprintf("Alert triggered when the audit log sink '%s' is changed (deleted or updated) for team %s in environment %s", sinkName, teamSlug, envName),
			MimeType: "text/markdown",
		},
		Combiner: "OR",
		Conditions: []*monitoring.Condition{
			{
				DisplayName: fmt.Sprintf("Sink change detected: %s", sinkName),
				ConditionMatchedLog: &monitoring.LogMatch{
					Filter: fmt.Sprintf(`resource.type="logging_sink"
(protoPayload.methodName="google.logging.v2.ConfigServiceV2.DeleteSink" OR protoPayload.methodName="google.logging.v2.ConfigServiceV2.UpdateSink")
protoPayload.resourceName="projects/%s/sinks/%s"`, teamProjectID, sinkName),
				},
			},
		},
		Enabled:              true,
		NotificationChannels: notificationChannels,
		AlertStrategy: &monitoring.AlertStrategy{
			AutoClose: "604800s", // 7 days
			NotificationRateLimit: &monitoring.NotificationRateLimit{
				Period: "300s", // 5 minutes
			},
		},
	}

	if existingPolicy != nil {
		// Update existing policy if notification channels have changed
		needsUpdate := false

		// Check if notification channels have changed
		if len(existingPolicy.NotificationChannels) != len(notificationChannels) {
			needsUpdate = true
		} else {
			// Check if the channels are different
			existingChannelsMap := make(map[string]bool)
			for _, channel := range existingPolicy.NotificationChannels {
				existingChannelsMap[channel] = true
			}
			for _, channel := range notificationChannels {
				if !existingChannelsMap[channel] {
					needsUpdate = true
					break
				}
			}
		}

		if needsUpdate {
			// Set the name and other required fields for update
			alertPolicy.Name = existingPolicy.Name
			alertPolicy.CreationRecord = existingPolicy.CreationRecord
			alertPolicy.MutationRecord = existingPolicy.MutationRecord

			// Update the alert policy
			updateCall := r.services.MonitoringService.Projects.AlertPolicies.Patch(existingPolicy.Name, alertPolicy)
			updatedPolicy, err := updateCall.Context(ctx).Do()
			if err != nil {
				return fmt.Errorf("update alert policy: %w", err)
			}
			log.Infof("Updated sink change alert policy %s for team %s environment %s", updatedPolicy.Name, teamSlug, envName)
		} else {
			log.Debugf("Alert policy %s already exists with correct configuration, skipping", alertPolicyName)
		}
	} else {
		// Create new alert policy
		createCall := r.services.MonitoringService.Projects.AlertPolicies.Create(parent, alertPolicy)
		createdPolicy, err := createCall.Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("create alert policy: %w", err)
		}
		log.Infof("Created sink change alert policy %s for team %s environment %s", createdPolicy.Name, teamSlug, envName)
	}

	return nil
}

// generateAlertPolicyName generates a consistent name for the alert policy
func (r *auditLogReconciler) generateAlertPolicyName(teamSlug, envName string) string {
	return fmt.Sprintf("audit-sink-changes-alert-%s-%s", teamSlug, envName)
}
