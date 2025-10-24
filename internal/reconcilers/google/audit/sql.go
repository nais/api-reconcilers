package audit

import (
	"context"
	"fmt"

	"google.golang.org/api/sqladmin/v1"
)

// getSQLInstancesForTeam retrieves SQL instances for a team that have pgaudit enabled.
func (r *auditLogReconciler) getSQLInstancesForTeam(ctx context.Context, teamSlug, teamProjectID string) ([]string, error) {
	// Check if we have a valid SQL admin service
	if r.services == nil || r.services.SQLAdminService == nil {
		return nil, fmt.Errorf("no SQL admin service available for team %s", teamSlug)
	}

	// Validate project ID
	if teamProjectID == "" {
		return nil, fmt.Errorf("team project ID is empty for team %s", teamSlug)
	}

	sqlInstances := make([]string, 0)
	response, err := r.services.SQLAdminService.Instances.List(teamProjectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list sql instances for team %s project %s: %w", teamSlug, teamProjectID, err)
	}
	for _, i := range response.Items {
		if HasPgAuditEnabled(i) {
			sqlInstances = append(sqlInstances, i.Name)
		}
	}
	return sqlInstances, nil
}

// HasPgAuditEnabled checks if a SQL instance has the pgaudit flag enabled.
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

// BuildLogFilter constructs a Cloud SQL audit log filter for all SQL instances in the project.
func (r *auditLogReconciler) BuildLogFilter(teamProjectID string) string {
	baseFilter := fmt.Sprintf(`resource.type="cloudsql_database"
AND logName="projects/%s/logs/cloudaudit.googleapis.com%%2Fdata_access"
AND protoPayload.request.@type="type.googleapis.com/google.cloud.sql.audit.v1.PgAuditEntry"`, teamProjectID)

	return baseFilter
}
