package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"
)

// ExtractServiceAccountEmail extracts the email from a writer identity that may have the format "serviceAccount:email@domain".
func ExtractServiceAccountEmail(writerIdentity string) string {
	if strings.HasPrefix(writerIdentity, "serviceAccount:") {
		return strings.TrimPrefix(writerIdentity, "serviceAccount:")
	}
	return writerIdentity
}

// waitForServiceAccountToExist waits for a service account to be created and become available for IAM operations.
func (r *auditLogReconciler) waitForServiceAccountToExist(ctx context.Context, serviceAccount string, log logrus.FieldLogger) error {
	if r.services == nil || r.services.IAMService == nil {
		log.Warning("no IAM service available, cannot verify service account existence")
		return nil // Don't fail if we can't verify
	}

	// Extract just the email part if the service account has the "serviceAccount:" prefix
	serviceAccountEmail := ExtractServiceAccountEmail(serviceAccount)

	const maxRetries = 10
	const baseDelay = 500 * time.Millisecond
	const maxDelay = 30 * time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Try to get the service account using just the email
		_, err := r.services.IAMService.Projects.ServiceAccounts.Get(fmt.Sprintf("projects/-/serviceAccounts/%s", serviceAccountEmail)).Context(ctx).Do()
		if err == nil {
			log.WithField("service_account", serviceAccountEmail).Debug("service account exists and is ready")
			return nil
		}

		// Check if it's a "not found" error (expected while service account is being created)
		if googleErr, ok := err.(*googleapi.Error); ok && googleErr.Code == 404 {
			if attempt == maxRetries-1 {
				return fmt.Errorf("service account %s still does not exist after waiting %d attempts", serviceAccountEmail, maxRetries)
			}

			// Calculate delay with exponential backoff
			delay := time.Duration(1<<attempt) * baseDelay
			if delay > maxDelay {
				delay = maxDelay
			}

			log.WithFields(logrus.Fields{
				"service_account": serviceAccountEmail,
				"attempt":         attempt + 1,
				"delay":           delay,
			}).Debug("service account not yet available, waiting for creation")

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
				continue
			}
		}

		// For other errors (like permission issues), return immediately
		log.WithFields(logrus.Fields{
			"service_account": serviceAccountEmail,
			"error":           err.Error(),
		}).Warning("unexpected error checking service account existence")
		return nil // Don't fail the reconciliation for verification issues
	}

	return fmt.Errorf("unexpected error in service account wait logic")
}

// retryIAMOperation performs an IAM operation with exponential backoff retry logic.
func (r *auditLogReconciler) retryIAMOperation(ctx context.Context, operation func() error, log logrus.FieldLogger) error {
	const maxRetries = 5
	const baseDelay = 100 * time.Millisecond
	const maxDelay = 5 * time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}

		// Check if it's a retryable error (409 conflict or 400 service account not found)
		if googleErr, ok := err.(*googleapi.Error); ok {
			isRetryable := false
			if googleErr.Code == 409 {
				// Concurrent policy changes
				isRetryable = true
			} else if googleErr.Code == 400 &&
				(strings.Contains(strings.ToLower(googleErr.Message), "service account") &&
					strings.Contains(strings.ToLower(googleErr.Message), "does not exist")) {
				// Service account doesn't exist yet
				isRetryable = true
			}

			if isRetryable {
				if attempt == maxRetries-1 {
					return fmt.Errorf("IAM operation failed after %d attempts: %w", maxRetries, err)
				}

				// Calculate delay with exponential backoff
				delay := time.Duration(1<<attempt) * baseDelay
				if delay > maxDelay {
					delay = maxDelay
				}

				var reason string
				if googleErr.Code == 409 {
					reason = "IAM policy conflict"
				} else {
					reason = "service account not yet available"
				}

				log.WithFields(logrus.Fields{
					"attempt": attempt + 1,
					"delay":   delay,
					"error":   err.Error(),
					"reason":  reason,
				}).Warning("retrying IAM operation with exponential backoff")

				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
					continue
				}
			}
		}

		// For non-retryable errors, return immediately
		return err
	}

	return fmt.Errorf("unexpected error in retry logic")
}

// grantBucketWritePermission grants the logging.bucketWriter role to the sink's writer identity.
func (r *auditLogReconciler) grantBucketWritePermission(ctx context.Context, bucketName, writerIdentity string, log logrus.FieldLogger) error {
	if r.services == nil || r.services.CloudResourceManagerService == nil {
		return fmt.Errorf("CloudResourceManagerService is not available")
	}

	// Wait for the service account to be created before granting permissions
	if err := r.waitForServiceAccountToExist(ctx, writerIdentity, log); err != nil {
		log.WithError(err).WithField("identity", writerIdentity).Warning("failed to verify service account existence, continuing with permission grant")
		// Continue anyway - the IAM operation might still work
	}

	operation := func() error {
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
			log.WithFields(logrus.Fields{
				"identity":   writerIdentity,
				"permission": bucketWriterRole,
			}).Debug("writer identity already has permission, skipping grant")
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

		log.WithFields(logrus.Fields{
			"identity":   writerIdentity,
			"permission": bucketWriterRole,
			"bucket":     bucketName,
		}).Info("granted bucket write permission")

		return nil
	}

	return r.retryIAMOperation(ctx, operation, log)
}

// grantTeamLogViewPermission grants the logging.viewAccessor role to the team's Google Group with IAM condition restricting access to only their specific log view.
func (r *auditLogReconciler) grantTeamLogViewPermission(ctx context.Context, bucketName, logViewName, teamGoogleGroup string, log logrus.FieldLogger) error {
	// Check if we have a valid Cloud Resource Manager service
	if r.services == nil || r.services.CloudResourceManagerService == nil {
		log.Warning("no Cloud Resource Manager service available, cannot grant team log view permission")
		return nil
	}

	operation := func() error {
		policy, err := r.services.CloudResourceManagerService.Projects.GetIamPolicy(r.config.ProjectID, &cloudresourcemanager.GetIamPolicyRequest{
			Options: &cloudresourcemanager.GetPolicyOptions{
				RequestedPolicyVersion: 3,
			},
		}).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("get project IAM policy: %w", err)
		}

		logViewAccessorRole := "roles/logging.viewAccessor"
		teamGroupMember := fmt.Sprintf("group:%s", teamGoogleGroup)

		// Create IAM condition to restrict access to only this team's _AllLogs view
		logViewPath := fmt.Sprintf("projects/%s/locations/%s/buckets/%s/views/%s", r.config.ProjectID, r.config.Location, bucketName, logViewName)
		conditionTitle := fmt.Sprintf("Access to %s %s view only", bucketName, logViewName)
		conditionDescription := fmt.Sprintf("Restricts logging.viewAccessor access to %s view on bucket %s for team %s", logViewName, bucketName, teamGoogleGroup)

		// IAM condition expression to limit access to logs stored in the specific log view
		// Use the correct resource name format for Cloud Logging log view access
		conditionExpression := fmt.Sprintf(`resource.name == "%s"`, logViewPath)

		targetCondition := &cloudresourcemanager.Expr{
			Title:       conditionTitle,
			Description: conditionDescription,
			Expression:  conditionExpression,
		}

		// Check if this team already has conditional access to this bucket
		hasPermission := false
		for _, binding := range policy.Bindings {
			if binding.Role == logViewAccessorRole && binding.Condition != nil {
				if binding.Condition.Title == conditionTitle {
					for _, member := range binding.Members {
						if member == teamGroupMember {
							hasPermission = true
							break
						}
					}
				}
			}
		}

		if hasPermission {
			log.WithFields(logrus.Fields{
				"identity":   teamGoogleGroup,
				"permission": logViewAccessorRole,
				"log_view":   logViewName,
			}).Debug("team already has conditional log view permission, skipping grant")
			return nil
		}

		// Look for existing conditional binding with the same condition or create new one
		foundBinding := false
		for _, binding := range policy.Bindings {
			if binding.Role == logViewAccessorRole && binding.Condition != nil && binding.Condition.Title == conditionTitle {
				// Add team to existing conditional binding
				binding.Members = append(binding.Members, teamGroupMember)
				foundBinding = true
				break
			}
		}

		if !foundBinding {
			// Create new conditional binding
			newBinding := &cloudresourcemanager.Binding{
				Role:      logViewAccessorRole,
				Members:   []string{teamGroupMember},
				Condition: targetCondition,
			}
			policy.Bindings = append(policy.Bindings, newBinding)
		}

		setRequest := &cloudresourcemanager.SetIamPolicyRequest{
			Policy: policy,
		}

		// Ensure we use policy version 3 for IAM conditions
		if setRequest.Policy != nil {
			setRequest.Policy.Version = 3
		}

		_, err = r.services.CloudResourceManagerService.Projects.SetIamPolicy(r.config.ProjectID, setRequest).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("set project IAM policy with condition: %w", err)
		}

		log.WithFields(logrus.Fields{
			"role":     logViewAccessorRole,
			"group":    teamGoogleGroup,
			"log_view": logViewName,
		}).Info("team can view their logs using the specified log view")
		return nil
	}

	return r.retryIAMOperation(ctx, operation, log)
}

// removeBucketWritePermission removes write permission for a service account from a bucket.
func (r *auditLogReconciler) removeBucketWritePermission(ctx context.Context, bucketName, writerIdentity string, log logrus.FieldLogger) error {
	if r.services == nil || r.services.CloudResourceManagerService == nil {
		return fmt.Errorf("CloudResourceManagerService is not available")
	}

	operation := func() error {
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
						}).Info("removing bucket write permission")
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
		}).Info("successfully removed bucket write permission")

		return nil
	}

	return r.retryIAMOperation(ctx, operation, log)
}

// removeTeamLogViewPermission removes the conditional logging.viewAccessor role from the team's Google Group.
func (r *auditLogReconciler) removeTeamLogViewPermission(ctx context.Context, teamGoogleGroup string, log logrus.FieldLogger) error {
	// Check if we have a valid Cloud Resource Manager service
	if r.services == nil || r.services.CloudResourceManagerService == nil {
		log.Warning("no Cloud Resource Manager service available, cannot remove team log view permission")
		return nil
	}

	operation := func() error {
		// Get current project IAM policy
		policy, err := r.services.CloudResourceManagerService.Projects.GetIamPolicy(r.config.ProjectID, &cloudresourcemanager.GetIamPolicyRequest{
			Options: &cloudresourcemanager.GetPolicyOptions{
				RequestedPolicyVersion: 3,
			},
		}).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("get project IAM policy: %w", err)
		}

		// Remove the member from conditional logging.viewAccessor role bindings
		role := "roles/logging.viewAccessor"
		teamGroupMember := fmt.Sprintf("group:%s", teamGoogleGroup)
		modified := false

		// We need to remove the team from any conditional bindings for this role
		// Since we don't know the specific bucket name in delete context, we look for any conditional binding with this team
		var bindingsToRemove []int
		for i, binding := range policy.Bindings {
			if binding.Role == role && binding.Condition != nil {
				// Look for conditional bindings that contain this team
				var newMembers []string
				teamFound := false
				for _, member := range binding.Members {
					if member != teamGroupMember {
						newMembers = append(newMembers, member)
					} else {
						teamFound = true
						modified = true
						log.WithFields(logrus.Fields{
							"group":     teamGoogleGroup,
							"role":      role,
							"condition": binding.Condition.Title,
						}).Info("removing team from conditional log view permission")
					}
				}

				if teamFound {
					if len(newMembers) == 0 {
						// If no members left, mark binding for removal
						bindingsToRemove = append(bindingsToRemove, i)
					} else {
						// Update binding with remaining members
						binding.Members = newMembers
					}
				}
			}
		}

		// Remove empty conditional bindings (in reverse order to maintain indices)
		for i := len(bindingsToRemove) - 1; i >= 0; i-- {
			bindingIndex := bindingsToRemove[i]
			policy.Bindings = append(policy.Bindings[:bindingIndex], policy.Bindings[bindingIndex+1:]...)
			log.WithField("role", role).Debug("removed empty conditional binding")
		}

		if !modified {
			log.WithField("group", teamGoogleGroup).Debug("team group not found in conditional log view permissions")
			return nil
		}

		// Set the updated policy
		setRequest := &cloudresourcemanager.SetIamPolicyRequest{
			Policy: policy,
		}

		// Ensure we use policy version 3 for IAM conditions
		if setRequest.Policy != nil {
			setRequest.Policy.Version = 3
		}

		_, err = r.services.CloudResourceManagerService.Projects.SetIamPolicy(r.config.ProjectID, setRequest).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("set project IAM policy: %w", err)
		}

		log.WithFields(logrus.Fields{
			"group": teamGoogleGroup,
			"role":  role,
		}).Info("successfully removed team from conditional log view permissions")

		return nil
	}

	return r.retryIAMOperation(ctx, operation, log)
}
