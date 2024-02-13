package google_token_source

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	admin_directory "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/impersonate"
)

type Builder struct {
	serviceAccountEmail string
	subjectEmail        string
}

func New(googleManagementProjectID, tenantDomain string) (*Builder, error) {
	if googleManagementProjectID == "" {
		return nil, fmt.Errorf("googleManagementProjectID can not be empty")
	}

	if tenantDomain == "" {
		return nil, fmt.Errorf("tenantDomain can not be empty")
	}

	return &Builder{
		serviceAccountEmail: "console@" + googleManagementProjectID + ".iam.gserviceaccount.com",
		subjectEmail:        "nais-console@" + tenantDomain,
	}, nil
}

func (g Builder) impersonateTokenSource(ctx context.Context, delegate bool, scopes []string) (oauth2.TokenSource, error) {
	impersonateConfig := impersonate.CredentialsConfig{
		TargetPrincipal: g.serviceAccountEmail,
		Scopes:          scopes,
	}
	if delegate {
		impersonateConfig.Subject = g.subjectEmail
	}

	return impersonate.CredentialsTokenSource(ctx, impersonateConfig)
}

func (g Builder) Admin(ctx context.Context) (oauth2.TokenSource, error) {
	return g.impersonateTokenSource(ctx, true, []string{
		admin_directory.AdminDirectoryUserReadonlyScope,
		admin_directory.AdminDirectoryGroupScope,
	})
}

func (g Builder) GCP(ctx context.Context) (oauth2.TokenSource, error) {
	return g.impersonateTokenSource(ctx, false, []string{
		cloudresourcemanager.CloudPlatformScope,
	})
}
