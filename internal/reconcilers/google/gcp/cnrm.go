package google_gcp_reconciler

import (
	"context"
	"fmt"
	"slices"

	"google.golang.org/api/iam/v1"
)

const CNRMRoleId = "CustomCNRMRole"

func (r *googleGcpReconciler) createCNRMRole(ctx context.Context, projectId string) (*iam.Role, error) {
	parent := fmt.Sprintf("projects/%s", projectId)
	name := fmt.Sprintf("projects/%s/roles/%s", projectId, CNRMRoleId)
	existingRole, _ := r.gcpServices.ProjectsRolesService.Get(name).Context(ctx).Do()

	role := &iam.Role{
		Title:       "NAIS Custom CNRM Role",
		Description: "Custom role for namespaced CNRM users to allow creation of GCP resources",
		Stage:       "GA",
		IncludedPermissions: []string{
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

	if existingRole == nil {
		req := &iam.CreateRoleRequest{
			Role:   role,
			RoleId: CNRMRoleId,
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
