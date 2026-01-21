package google_gcp_reconciler

import (
	"context"
	"fmt"
	"slices"

	"google.golang.org/api/iam/v1"
)

func (r *googleGcpReconciler) createOrUpdateRole(ctx context.Context, projectId, roleId string, role *iam.Role) (*iam.Role, error) {
	parent := fmt.Sprintf("projects/%s", projectId)
	name := fmt.Sprintf("projects/%s/roles/%s", projectId, roleId)
	existingRole, _ := r.gcpServices.ProjectsRolesService.Get(name).Context(ctx).Do()

	if existingRole == nil {
		req := &iam.CreateRoleRequest{
			Role:   role,
			RoleId: roleId,
		}
		return r.gcpServices.ProjectsRolesService.Create(parent, req).Context(ctx).Do()
	}

	slices.Sort(existingRole.IncludedPermissions)
	slices.Sort(role.IncludedPermissions)

	if !slices.Equal(existingRole.IncludedPermissions, role.IncludedPermissions) {
		return r.gcpServices.ProjectsRolesService.Patch(name, role).Context(ctx).Do()
	}

	return existingRole, nil
}

func (r *googleGcpReconciler) createTeamRole(ctx context.Context, projectId string) (*iam.Role, error) {
	role := &iam.Role{
		Title:       "NAIS Custom Team Role",
		Description: "Custom role for members of a Nais team",
		Stage:       "GA",
		IncludedPermissions: []string{
			"cloudsql.databases.delete",
			"cloudsql.databases.get",
			"cloudsql.databases.list",
			"cloudsql.databases.update",
			"cloudsql.instances.delete",
			"cloudsql.instances.get",
			"cloudsql.instances.list",
			"cloudsql.instances.update",
			"cloudsql.users.create",
			"cloudsql.users.delete",
			"cloudsql.users.list",
			"cloudsql.users.update",
			"resourcemanager.projects.get",
			"resourcemanager.projects.getIamPolicy",
			"storage.buckets.get",
			"storage.buckets.getIamPolicy",
			"storage.buckets.list",
			"storage.buckets.update",
			"storage.buckets.delete",
			"bigquery.datasets.get",
			"bigquery.datasets.getIamPolicy",
			"bigquery.models.getData",
			"bigquery.models.getMetadata",
			"bigquery.models.list",
			"bigquery.routines.get",
			"bigquery.routines.list",
			"bigquery.tables.get",
			"bigquery.tables.getData",
			"bigquery.tables.getIamPolicy",
			"bigquery.tables.list",
			"bigquery.tables.replicateData",
		},
	}

	return r.createOrUpdateRole(ctx, projectId, "CustomTeamRole", role)
}

func (r *googleGcpReconciler) createCNRMRole(ctx context.Context, projectId string) (*iam.Role, error) {
	role := &iam.Role{
		Title:       "NAIS Custom CNRM Role",
		Description: "Custom role for namespaced CNRM users to allow creation of GCP resources",
		Stage:       "GA",
		IncludedPermissions: []string{
			"iam.serviceAccounts.create",
			"iam.serviceAccounts.delete",
			"iam.serviceAccounts.get",
			"iam.serviceAccounts.getIamPolicy",
			"iam.serviceAccounts.list",
			"iam.serviceAccounts.setIamPolicy",
			"iam.serviceAccounts.update",
			"cloudkms.cryptoKeys.create",
			"cloudkms.cryptoKeys.get",
			"cloudkms.cryptoKeys.update",
			"cloudkms.keyRings.create",
			"cloudkms.keyRings.get",
			"cloudkms.keyRings.getIamPolicy",
			"cloudkms.keyRings.setIamPolicy",
			"cloudsql.databases.create",
			"cloudsql.databases.delete",
			"cloudsql.databases.get",
			"cloudsql.databases.list",
			"cloudsql.databases.update",
			"cloudsql.instances.create",
			"cloudsql.instances.delete",
			"cloudsql.instances.get",
			"cloudsql.instances.list",
			"cloudsql.instances.update",
			"cloudsql.users.create",
			"cloudsql.users.delete",
			"cloudsql.users.list",
			"cloudsql.users.update",
			"resourcemanager.projects.get",
			"resourcemanager.projects.getIamPolicy",
			"resourcemanager.projects.setIamPolicy",
			"storage.buckets.create",
			"storage.buckets.get",
			"storage.buckets.getIamPolicy",
			"storage.buckets.list",
			"storage.buckets.setIamPolicy",
			"storage.buckets.update",
			"storage.buckets.delete",
			"cloudsql.sslCerts.create",
			"cloudsql.sslCerts.delete",
			"cloudsql.sslCerts.get",
			"cloudsql.sslCerts.list",
		},
	}

	return r.createOrUpdateRole(ctx, projectId, "CustomCNRMRole", role)
}
