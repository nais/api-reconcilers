package audit

import (
	"context"
	"fmt"

	logging "cloud.google.com/go/logging/apiv2"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/iterator"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
	monitoring "google.golang.org/api/monitoring/v3"
	"google.golang.org/api/sqladmin/v1"
)

const (
	reconcilerName = "google:gcp:audit"

	configRetentionDays = "audit:retention_days"
	configLocked        = "audit:locked"
)

// Services contains all the GCP services needed for audit log reconciliation.
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

// Config holds the configuration for the audit log reconciler.
type Config struct {
	ProjectID string
	Location  string
}

// OverrideFunc allows for dependency injection in tests.
type OverrideFunc func(reconciler *auditLogReconciler)

// Name returns the reconciler name.
func (r *auditLogReconciler) Name() string {
	return reconcilerName
}

// New creates a new audit log reconciler.
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

// Configuration returns the reconciler configuration specification.
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
		},
	}
}

// Delete handles team deletion by cleaning up all associated audit log resources.
func (r *auditLogReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})

	for it.Next() {
		env := it.Value()

		// Check if the environment has a GCP project ID
		if env.GcpProjectId == nil {
			log.WithFields(logrus.Fields{
				"team":        naisTeam.Slug,
				"environment": env.EnvironmentName,
			}).Debug("skipping environment without GCP project ID")
			continue
		}

		teamProjectID := *env.GcpProjectId
		if teamProjectID == "" {
			log.WithFields(logrus.Fields{
				"team":        naisTeam.Slug,
				"environment": env.EnvironmentName,
			}).Debug("skipping environment with empty GCP project ID")
			continue
		}

		// Since SQL instances may already be deleted when a team is deleted,
		// we need to find all existing sinks for this team/environment
		// instead of relying on the existence of SQL instances
		err := r.deleteAllTeamSinks(ctx, teamProjectID, naisTeam.Slug, env.EnvironmentName, log)
		if err != nil {
			log.WithError(err).Warning("failed to delete all team sinks")
			// Continue with other environments instead of failing completely
		}

		// Check if the log bucket exists and delete it if it's not locked
		bucketName := GenerateLogBucketName(naisTeam.Slug, env.EnvironmentName)
		bucketPath := fmt.Sprintf("projects/%s/locations/%s/buckets/%s", r.config.ProjectID, r.config.Location, bucketName)

		// Check if we have a valid logging service
		if r.services == nil || r.services.LogConfigService == nil {
			log.WithField("bucket", bucketName).Debug("no logging service available, cannot check or delete bucket")
		} else {
			exists, err := r.bucketExists(ctx, bucketPath)
			if err != nil {
				log.WithError(err).WithField("bucket", bucketName).Warning("failed to check if bucket exists")
			} else if exists {
				// Get bucket information to check if it's locked
				bucket, err := r.getBucketInfo(ctx, bucketPath)
				if err != nil {
					log.WithError(err).WithField("bucket", bucketName).Warning("failed to get bucket information")
				} else if !bucket.Locked {
					// Delete the bucket if it's not locked
					log.WithField("bucket", bucketName).Info("deleting unlocked log bucket")
					err = r.deleteBucket(ctx, bucketPath, log)
					if err != nil {
						log.WithError(err).WithField("bucket", bucketName).Warning("failed to delete bucket")
						// Continue with other operations instead of failing completely
					}
				} else {
					log.WithField("bucket", bucketName).Info("bucket is locked, skipping deletion")
				}
			} else {
				log.WithField("bucket", bucketName).Debug("bucket does not exist, skipping deletion")
			}
		}
	}

	// Remove team log view permission after all sinks are deleted
	if naisTeam.GoogleGroupEmail != nil {
		log.Debugf("removing log view permission for team group: %s", *naisTeam.GoogleGroupEmail)
		err := r.removeTeamLogViewPermission(ctx, *naisTeam.GoogleGroupEmail, log)
		if err != nil {
			log.WithError(err).Warning("failed to remove team log view permission")
			// Don't fail the deletion process if permission removal fails
		}
	} else {
		log.WithField("team", naisTeam.Slug).Debug("no Google Group email found, skipping team log view permission removal")
	}

	return it.Err()
}

// Reconcile handles the main reconciliation logic for audit logs.
func (r *auditLogReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	it := iterator.New(ctx, 100, func(limit, offset int64) (*protoapi.ListTeamEnvironmentsResponse, error) {
		return client.Teams().Environments(ctx, &protoapi.ListTeamEnvironmentsRequest{Limit: limit, Offset: offset, Slug: naisTeam.Slug})
	})

	for it.Next() {
		env := it.Value()

		// Check if the environment has a GCP project ID
		if env.GcpProjectId == nil {
			log.WithFields(logrus.Fields{
				"team":        naisTeam.Slug,
				"environment": env.EnvironmentName,
			}).Debug("skipping environment without GCP project ID")
			continue
		}

		teamProjectID := *env.GcpProjectId
		if teamProjectID == "" {
			log.WithFields(logrus.Fields{
				"team":        naisTeam.Slug,
				"environment": env.EnvironmentName,
			}).Debug("skipping environment with empty GCP project ID")
			continue
		}

		// Get SQL instances for this team/environment
		listSQLInstances, err := r.getSQLInstancesForTeam(ctx, naisTeam.Slug, teamProjectID)
		if err != nil {
			return fmt.Errorf("get sql instances for team %s: %w", naisTeam.Slug, err)
		}

		// Skip if no SQL instances with pgaudit enabled
		if len(listSQLInstances) == 0 {
			log.WithFields(logrus.Fields{
				"team":        naisTeam.Slug,
				"environment": env.EnvironmentName,
			}).Debug("skipping environment without SQL instances with pgaudit enabled")
			continue
		}

		// Create one log bucket per team environment (shared by all SQL instances)
		bucketName, err := r.createOrUpdateLogBucketIfNeeded(ctx, client, naisTeam.Slug, env.EnvironmentName, r.config.Location, log)
		if err != nil {
			return fmt.Errorf("create or update log bucket for team %s environment %s: %w", naisTeam.Slug, env.EnvironmentName, err)
		}

		// Verify that the _AllLogs view exists on the bucket (should be automatic, but check as precaution)
		err = r.verifyLogViewExists(ctx, bucketName, "_AllLogs", log)
		if err != nil {
			return fmt.Errorf("verify _AllLogs view exists for team %s environment %s: %w", naisTeam.Slug, env.EnvironmentName, err)
		}

		// Create one log sink per team environment covering all SQL instances (auditing all database users)
		_, writerIdentity, err := r.createOrUpdateLogSinkIfNeeded(ctx, teamProjectID, naisTeam.Slug, env.EnvironmentName, bucketName, log)
		if err != nil {
			return fmt.Errorf("create or update log sink for team %s environment %s: %w", naisTeam.Slug, env.EnvironmentName, err)
		}

		if writerIdentity != "" {
			log.WithField("identity", writerIdentity).Debug("granting bucket write permission for sink writer identity")
			err = r.grantBucketWritePermission(ctx, bucketName, writerIdentity, log)
			if err != nil {
				return fmt.Errorf("grant bucket write permission for team %s environment %s: %w", naisTeam.Slug, env.EnvironmentName, err)
			}
		} else {
			log.Debug("no writer identity found for sink, skipping permission grant")
		}

		// Grant log view permission to team members
		if naisTeam.GoogleGroupEmail != nil {
			log.WithField("team", naisTeam.Slug).Debug("granting log view permission for team group")
			err = r.grantTeamLogViewPermission(ctx, bucketName, "_AllLogs", *naisTeam.GoogleGroupEmail, log)
			if err != nil {
				return fmt.Errorf("grant team log view permission for team %s environment %s: %w", naisTeam.Slug, env.EnvironmentName, err)
			}
		} else {
			log.WithField("team", naisTeam.Slug).Debug("no Google Group email found, skipping team log view permission grant")
		}
	}

	return it.Err()
}
