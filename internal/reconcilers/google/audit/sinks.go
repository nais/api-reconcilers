package audit

import (
	"context"
	"fmt"
	"regexp"

	"cloud.google.com/go/logging/apiv2/loggingpb"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// createOrUpdatePostgresLogSinkIfNeeded creates or updates a Postgres audit log sink for the team environment.
func (r *auditLogReconciler) createOrUpdatePostgresLogSinkIfNeeded(ctx context.Context, teamProjectID, teamSlug, envName, bucketName string, log logrus.FieldLogger) (string, string, error) {
	sinkName := GeneratePostgresLogSinkName(teamSlug, envName)
	filter := r.BuildPostgresLogFilter(teamProjectID)
	description := fmt.Sprintf("Postgres audit log sink for team %s environment %s (created by api-reconcilers)", teamSlug, envName)
	return r.createOrUpdateLogSink(ctx, teamProjectID, sinkName, filter, description, bucketName, teamSlug, envName, log)
}

// createOrUpdateLogSinkIfNeeded creates or updates a log sink for the team environment.
func (r *auditLogReconciler) createOrUpdateLogSinkIfNeeded(ctx context.Context, teamProjectID, teamSlug, envName, bucketName string, log logrus.FieldLogger) (string, string, error) {
	sinkName := GenerateLogSinkName(teamSlug, envName)
	filter := r.BuildLogFilter(teamProjectID)
	description := fmt.Sprintf("Audit log sink for team %s environment %s (created by api-reconcilers)", teamSlug, envName)
	return r.createOrUpdateLogSink(ctx, teamProjectID, sinkName, filter, description, bucketName, teamSlug, envName, log)
}

// createOrUpdateLogSink is the common implementation for creating or updating log sinks.
func (r *auditLogReconciler) createOrUpdateLogSink(ctx context.Context, teamProjectID, sinkName, filter, description, bucketName, teamSlug, envName string, log logrus.FieldLogger) (string, string, error) {
	parent := fmt.Sprintf("projects/%s", teamProjectID)
	destination := fmt.Sprintf("logging.googleapis.com/projects/%s/locations/%s/buckets/%s", r.config.ProjectID, r.config.Location, bucketName)

	if err := ValidateLogSinkName(sinkName); err != nil {
		return "", "", fmt.Errorf("invalid sink name %q: %w", sinkName, err)
	}

	sinkPath := fmt.Sprintf("%s/sinks/%s", parent, sinkName)
	exists, err := r.sinkExists(ctx, sinkPath)
	if err != nil {
		return "", "", fmt.Errorf("check if sink exists: %w", err)
	}

	if !exists {
		return r.createSink(ctx, parent, sinkName, destination, filter, description, teamSlug, envName, log)
	}

	return r.updateSinkIfNeeded(ctx, sinkPath, sinkName, destination, filter, teamSlug, envName, log)
}

// createSink creates a new log sink.
func (r *auditLogReconciler) createSink(ctx context.Context, parent, sinkName, destination, filter, description, teamSlug, envName string, log logrus.FieldLogger) (string, string, error) {
	sinkReq := &loggingpb.CreateSinkRequest{
		Parent:               parent,
		UniqueWriterIdentity: true,
		Sink: &loggingpb.LogSink{
			Name:        sinkName,
			Destination: destination,
			Filter:      filter,
			Description: description,
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

	return sinkName, sink.WriterIdentity, nil
}

// updateSinkIfNeeded checks if a sink needs updates and applies them if necessary.
func (r *auditLogReconciler) updateSinkIfNeeded(ctx context.Context, sinkPath, sinkName, destination, filter, teamSlug, envName string, log logrus.FieldLogger) (string, string, error) {
	existingSink, err := r.services.LogConfigService.GetSink(ctx, &loggingpb.GetSinkRequest{
		SinkName: sinkPath,
	})
	if err != nil {
		return "", "", fmt.Errorf("get existing sink: %w", err)
	}

	updateMask := []string{}

	if existingSink.Filter != filter {
		updateMask = append(updateMask, "filter")
		log.WithField("sink", sinkName).Debug("sink filter will be updated")
	}

	if existingSink.Destination != destination {
		updateMask = append(updateMask, "destination")
		log.WithFields(logrus.Fields{
			"old_destination": existingSink.Destination,
			"new_destination": destination,
		}).Debug("sink destination will be updated")
	}

	if len(updateMask) == 0 {
		log.WithField("sink", sinkName).Debug("log sink already exists with correct configuration, skipping")
		return sinkName, existingSink.WriterIdentity, nil
	}

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

	return sinkName, updatedSink.WriterIdentity, nil
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

// deleteAllTeamSinks deletes the managed sinks for a specific team/environment.
func (r *auditLogReconciler) deleteAllTeamSinks(ctx context.Context, teamProjectID, teamSlug, envName string, log logrus.FieldLogger) error {
	// Check if we have a valid logging service
	if r.services == nil || r.services.LogConfigService == nil {
		log.Warning("no logging service available, cannot delete sinks")
		return nil // Return nil to not fail the overall deletion process
	}

	// Try to delete both SQL and Postgres sinks
	sinkNames := []string{
		GenerateLogSinkName(teamSlug, envName),
		GeneratePostgresLogSinkName(teamSlug, envName),
	}

	for _, sinkName := range sinkNames {
		parent := fmt.Sprintf("projects/%s", teamProjectID)
		sinkPath := fmt.Sprintf("%s/sinks/%s", parent, sinkName)

		// Get the sink to retrieve writer identity and destination before deleting
		sink, err := r.services.LogConfigService.GetSink(ctx, &loggingpb.GetSinkRequest{
			SinkName: sinkPath,
		})
		if err != nil {
			if status.Code(err) == codes.NotFound {
				log.WithField("sink", sinkName).Debug("sink does not exist, skipping")
				continue
			}
			log.WithError(err).WithField("sink", sinkName).Warning("failed to get sink information")
			continue
		}

		log.WithField("sink", sinkName).Info("found managed sink for deletion")

		// Get the sink's writer identity and bucket name before deleting
		writerIdentity := sink.WriterIdentity
		bucketName := r.extractBucketNameFromDestination(sink.Destination)

		// Delete the log sink
		err = r.deleteSink(ctx, teamProjectID, sinkName, log)
		if err != nil {
			log.WithError(err).WithField("sink", sinkName).Error("failed to delete log sink")
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

	return nil
}
