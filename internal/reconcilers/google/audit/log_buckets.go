package audit

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/logging/apiv2/loggingpb"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// createOrUpdateLogBucketIfNeeded creates or updates a log bucket based on configuration.
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
		log.WithFields(logrus.Fields{
			"log_bucket":  bucket.Name,
			"team":        teamSlug,
			"environment": envName,
		}).Info("created log bucket")
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
			log.WithFields(logrus.Fields{
				"log_bucket":    bucketName,
				"old_retention": existingBucket.RetentionDays,
				"new_retention": retentionDays,
			}).Debug("updating bucket retention days")
		} else if existingBucket.Locked && existingBucket.RetentionDays != retentionDays {
			log.WithFields(logrus.Fields{
				"log_bucket":    bucketName,
				"old_retention": existingBucket.RetentionDays,
				"new_retention": retentionDays,
			}).Warn("bucket is locked, skipping retention days update")
		}

		// Check if locked status needs updating (can only go from false to true)
		if !existingBucket.Locked && locked {
			needsUpdate = true
			updateMask = append(updateMask, "locked")
			log.WithField("log_bucket", bucketName).Info("locking bucket")
		} else if existingBucket.Locked && !locked {
			log.WithField("log_bucket", bucketName).Warn("bucket is already locked, cannot unlock it")
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
			log.WithFields(logrus.Fields{
				"log_bucket":  updatedBucket.Name,
				"team":        teamSlug,
				"environment": envName,
			}).Info("updated log bucket")
		} else {
			log.WithField("log_bucket", bucketName).Debug("log bucket already exists with correct configuration, skipping")
		}
	}

	return bucketName, nil
}

// verifyLogViewExists checks that the specified log view exists on the bucket (as a precaution).
func (r *auditLogReconciler) verifyLogViewExists(ctx context.Context, bucketName, viewName string, log logrus.FieldLogger) error {
	logViewPath := fmt.Sprintf("projects/%s/locations/%s/buckets/%s/views/%s", r.config.ProjectID, r.config.Location, bucketName, viewName)

	_, err := r.services.LogConfigService.GetView(ctx, &loggingpb.GetViewRequest{Name: logViewPath})
	if err != nil {
		s, ok := status.FromError(err)
		if ok && s.Code() == codes.NotFound {
			return fmt.Errorf("log view %s does not exist on bucket %s (this should be automatically created by Google Cloud)", viewName, bucketName)
		}
		return fmt.Errorf("failed to verify log view %s exists: %w", viewName, err)
	}

	log.WithFields(logrus.Fields{
		"view":       viewName,
		"log_bucket": bucketName,
	}).Debug("verified that log view exists on bucket")

	return nil
}

// bucketExists checks if a log bucket exists.
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

// getRetentionDays retrieves the retention days configuration.
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

// getBucketLocked retrieves the bucket locked configuration.
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

// getBucketInfo retrieves information about a log bucket.
func (r *auditLogReconciler) getBucketInfo(ctx context.Context, bucketPath string) (*loggingpb.LogBucket, error) {
	bucket, err := r.services.LogConfigService.GetBucket(ctx, &loggingpb.GetBucketRequest{Name: bucketPath})
	if err != nil {
		return nil, err
	}
	return bucket, nil
}

// deleteBucket deletes a log bucket.
func (r *auditLogReconciler) deleteBucket(ctx context.Context, bucketPath string, log logrus.FieldLogger) error {
	req := &loggingpb.DeleteBucketRequest{
		Name: bucketPath,
	}

	err := r.services.LogConfigService.DeleteBucket(ctx, req)
	if err != nil {
		// Check if the bucket was already deleted
		if status.Code(err) == codes.NotFound {
			log.WithField("bucket", bucketPath).Debug("bucket already deleted")
			return nil
		}
		return fmt.Errorf("delete bucket %s: %w", bucketPath, err)
	}

	log.WithField("bucket", bucketPath).Info("successfully deleted log bucket")
	return nil
}
