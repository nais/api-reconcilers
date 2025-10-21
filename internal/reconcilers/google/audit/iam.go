package audit

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"google.golang.org/api/cloudresourcemanager/v1"
)

// grantBucketWritePermission grants the logging.bucketWriter role to the sink's writer identity.
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

// grantTeamLogViewPermission grants the logging.viewAccessor role to the team's Google Group with IAM condition restricting access to only their specific log view.
func (r *auditLogReconciler) grantTeamLogViewPermission(ctx context.Context, bucketName, logViewName, teamGoogleGroup string, log logrus.FieldLogger) error {
	// Check if we have a valid Cloud Resource Manager service
	if r.services == nil || r.services.CloudResourceManagerService == nil {
		log.Warn("No Cloud Resource Manager service available, cannot grant team log view permission")
		return nil // Return nil to not fail the overall reconciliation process
	}

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
		log.Debugf("Team group %s already has conditional %s permission for log view %s, skipping grant", teamGoogleGroup, logViewAccessorRole, logViewName)
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

	log.Infof("Granted conditional %s permission to team group %s for log view %s only", logViewAccessorRole, teamGoogleGroup, logViewName)
	log.Infof("Team can view their logs using: gcloud logging read 'logName:\"projects/%s/logs/cloudaudit.googleapis.com%%2Fdata_access\"' --log-view='%s' --project=%s", r.config.ProjectID, logViewPath, r.config.ProjectID)
	return nil
}

// removeBucketWritePermission removes write permission for a service account from a bucket.
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

// removeTeamLogViewPermission removes the conditional logging.viewAccessor role from the team's Google Group.
func (r *auditLogReconciler) removeTeamLogViewPermission(ctx context.Context, teamGoogleGroup string, log logrus.FieldLogger) error {
	// Check if we have a valid Cloud Resource Manager service
	if r.services == nil || r.services.CloudResourceManagerService == nil {
		log.Warn("No Cloud Resource Manager service available, cannot remove team log view permission")
		return nil // Return nil to not fail the overall deletion process
	}

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
					}).Info("Removing team from conditional log view permission")
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
		log.Debugf("Removed empty conditional binding for %s", role)
	}

	if !modified {
		log.WithField("group", teamGoogleGroup).Debug("Team group not found in conditional log view permissions")
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
	}).Info("Successfully removed team from conditional log view permissions")

	return nil
}
