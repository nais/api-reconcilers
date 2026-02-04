package audit

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"cloud.google.com/go/logging/apiv2/loggingpb"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func (r *auditLogReconciler) createOrUpdatePostgresLogSinkIfNeeded(ctx context.Context, teamProjectID, teamSlug, envName, bucketName string, log logrus.FieldLogger) (string, string, error) {
	parent := fmt.Sprintf("projects/%s", teamProjectID)
	sinkName := GeneratePostgresLogSinkName(teamSlug, envName)
	destination := fmt.Sprintf("logging.googleapis.com/projects/%s/locations/%s/buckets/%s", r.config.ProjectID, r.config.Location, bucketName)

	filter := r.BuildPostgresLogFilter(teamProjectID)

	if err := ValidateLogSinkName(sinkName); err != nil {
		return "", "", fmt.Errorf("invalid sink name %q: %w", sinkName, err)
	}

	sinkPath := fmt.Sprintf("%s/sinks/%s", parent, sinkName)
	exists, err := r.sinkExists(ctx, sinkPath)
	if err != nil {
		return "", "", fmt.Errorf("check if postgres log sink exists: %w", err)
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
				Description: fmt.Sprintf("Postgres audit log sink for team %s environment %s (created by api-reconcilers)", teamSlug, envName),
			},
		}

		sink, err := r.services.LogConfigService.CreateSink(ctx, sinkReq)
		if err != nil {
			return "", "", fmt.Errorf("create postgres log sink: %w", err)
		}
		log.WithFields(logrus.Fields{
			"team":        teamSlug,
			"environment": envName,
		}).Info("created postgres audit log sink")
		writerIdentity = sink.WriterIdentity
	} else {
		// Check if existing sink needs updates
		existingSink, err := r.services.LogConfigService.GetSink(ctx, &loggingpb.GetSinkRequest{
			SinkName: sinkPath,
		})
		if err != nil {
			return "", "", fmt.Errorf("get existing postgres log sink: %w", err)
		}

		needsUpdate := false
		updateMask := []string{}

		// Check if filter needs updating
		if existingSink.Filter != filter {
			needsUpdate = true
			updateMask = append(updateMask, "filter")
			log.WithField("sink", sinkName).Debug("sink filter will be updated")
		}

		// Check if destination needs updating (less common but possible)
		if existingSink.Destination != destination {
			needsUpdate = true
			updateMask = append(updateMask, "destination")
			log.WithFields(logrus.Fields{
				"old_destination": existingSink.Destination,
				"new_destination": destination,
			}).Debug("sink destination will be updated")
		}

		if needsUpdate {
			// Update the sink
			updateReq := &loggingpb.UpdateSinkRequest{
				SinkName:             sinkPath,
				UniqueWriterIdentity: true,
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
				return "", "", fmt.Errorf("update postgres audit log sink: %w", err)
			}
			log.WithFields(logrus.Fields{
				"team":        teamSlug,
				"environment": envName,
			}).Info("updated postgres audit log sink")
			writerIdentity = updatedSink.WriterIdentity
		} else {
			log.WithField("sink", sinkName).Debug("postgres audit log sink already exists with correct configuration, skipping")
			writerIdentity = existingSink.WriterIdentity
		}
	}

	return sinkName, writerIdentity, nil
}

// createOrUpdateLogSinkIfNeeded creates or updates a log sink for the team environment.
func (r *auditLogReconciler) createOrUpdateLogSinkIfNeeded(ctx context.Context, teamProjectID, teamSlug, envName, bucketName string, log logrus.FieldLogger) (string, string, error) {
	parent := fmt.Sprintf("projects/%s", teamProjectID)
	sinkName := GenerateLogSinkName(teamSlug, envName)
	destination := fmt.Sprintf("logging.googleapis.com/projects/%s/locations/%s/buckets/%s", r.config.ProjectID, r.config.Location, bucketName)

	filter := r.BuildLogFilter(teamProjectID)

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
		log.WithFields(logrus.Fields{
			"team":        teamSlug,
			"environment": envName,
		}).Info("created log sink")
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
			log.WithField("sink", sinkName).Debug("sink filter will be updated")
		}

		// Check if destination needs updating (less common but possible)
		if existingSink.Destination != destination {
			needsUpdate = true
			updateMask = append(updateMask, "destination")
			log.WithFields(logrus.Fields{
				"old_destination": existingSink.Destination,
				"new_destination": destination,
			}).Debug("sink destination will be updated")
		}

		if needsUpdate {
			// Update the sink
			updateReq := &loggingpb.UpdateSinkRequest{
				SinkName:             sinkPath,
				UniqueWriterIdentity: true,
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
			log.WithFields(logrus.Fields{
				"team":        teamSlug,
				"environment": envName,
			}).Info("updated log sink")
			writerIdentity = updatedSink.WriterIdentity
		} else {
			log.WithField("sink", sinkName).Debug("log sink already exists with correct configuration, skipping")
			writerIdentity = existingSink.WriterIdentity
		}
	}

	return sinkName, writerIdentity, nil
}

// sinkExists checks if a log sink exists.
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

// deleteSink removes a log sink.
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
			log.WithField("sink", sinkName).Debug("sink already deleted")
			return nil
		}
		return fmt.Errorf("delete sink %s: %w", sinkName, err)
	}

	log.WithField("sink", sinkName).Info("successfully deleted log sink")
	return nil
}

// isManagedSink checks if a sink was created by this reconciler for the given team and environment.
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

// extractBucketNameFromDestination extracts the bucket name from a log sink destination.
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

// deleteAllTeamSinks finds and deletes all sinks created by this reconciler for a specific team/environment.
func (r *auditLogReconciler) deleteAllTeamSinks(ctx context.Context, teamProjectID, teamSlug, envName string, log logrus.FieldLogger) error {
	// Check if we have a valid logging service
	if r.services == nil || r.services.LogConfigService == nil {
		log.Warning("no logging service available, cannot list or delete sinks")
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
			if errors.Is(err, iterator.Done) {
				break
			}
			return fmt.Errorf("failed to iterate sinks: %w", err)
		}

		// Check if this sink was created by our reconciler for this team/environment
		if r.isManagedSink(sink, teamSlug, envName) {
			log.WithField("sink", sink.Name).Info("found managed sink for deletion")

			// Get the sink's writer identity before deleting it
			writerIdentity := sink.WriterIdentity

			// Extract bucket name from destination to remove IAM permissions
			bucketName := r.extractBucketNameFromDestination(sink.Destination)

			// Delete the log sink
			err = r.deleteSink(ctx, teamProjectID, sink.Name, log)
			if err != nil {
				log.WithError(err).WithField("sink", sink.Name).Error("failed to delete log sink")
				// Continue with other sinks instead of failing completely
				continue
			}

			// Remove IAM permissions from bucket if we have a writer identity and bucket name
			if writerIdentity != "" && bucketName != "" {
				err = r.removeBucketWritePermission(ctx, bucketName, writerIdentity, log)
				if err != nil {
					log.WithFields(logrus.Fields{
						"bucket":   bucketName,
						"identity": writerIdentity,
					}).Warning("failed to remove bucket write permission")
				}
			}
		}
	}

	return nil
}
