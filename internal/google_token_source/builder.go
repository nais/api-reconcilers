package google_token_source

import (
	"context"

	"golang.org/x/oauth2"
	admin_directory "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/impersonate"
)

func WorkspaceAdminTokenSource(ctx context.Context, adminServiceAccountEmail, adminUserEmail string) (oauth2.TokenSource, error) {
	return impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		Scopes: []string{
			admin_directory.AdminDirectoryUserReadonlyScope,
			admin_directory.AdminDirectoryGroupScope,
		},
		Subject:         adminUserEmail,
		TargetPrincipal: adminServiceAccountEmail,
	})
}

func GcpTokenSource(ctx context.Context, serviceAccountEmail string) (oauth2.TokenSource, error) {
	return impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		Scopes: []string{
			cloudresourcemanager.CloudPlatformScope,
		},
		TargetPrincipal: serviceAccountEmail,
	})
}
