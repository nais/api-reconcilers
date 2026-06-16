package audit

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/api/sqladmin/v1"
)

func (r *auditLogReconciler) getSQLInstancesForTeam(ctx context.Context, teamSlug, teamProjectID string) ([]string, error) {
	if r.services == nil || r.services.SQLAdminService == nil {
		return nil, fmt.Errorf("no SQL admin service available for team %s", teamSlug)
	}

	if teamProjectID == "" {
		return nil, fmt.Errorf("team project ID is empty for team %s", teamSlug)
	}

	sqlInstances := make([]string, 0)
	response, err := r.services.SQLAdminService.Instances.List(teamProjectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list sql instances for team %s project %s: %w", teamSlug, teamProjectID, err)
	}
	for _, i := range response.Items {
		if HasCloudSQLAuditEnabled(i) {
			sqlInstances = append(sqlInstances, i.Name)
		}
	}
	return sqlInstances, nil
}

func HasCloudSQLAuditEnabled(instance *sqladmin.DatabaseInstance) bool {
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

// BuildLogFilter constructs a Logs Explorer filter based on which logging
func BuildLogFilter(teamProjectID string, hasCloudSQLAudit, requiresOnPremPostgresLogging bool) string {
	clauses := make([]string, 0, 2)

	if hasCloudSQLAudit {
		clauses = append(clauses, fmt.Sprintf(`(resource.type="cloudsql_database" `+
			`AND logName="projects/%s/logs/cloudaudit.googleapis.com%%2Fdata_access" `+
			`AND protoPayload.request.@type="type.googleapis.com/google.cloud.sql.audit.v1.PgAuditEntry")`,
			teamProjectID))
	}

	if requiresOnPremPostgresLogging {
		clauses = append(clauses, `(jsonPayload.requestType="dbAuditEntry")`)
	}

	return strings.Join(clauses, " OR ")
}
