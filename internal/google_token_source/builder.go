package google_token_source

import (
	"context"
	"fmt"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	admin_directory "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
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
		serviceAccountEmail: fmt.Sprintf("console@%s.iam.gserviceaccount.com", googleManagementProjectID),
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

	return impersonate.CredentialsTokenSource(ctx, impersonateConfig, option.WithHTTPClient(otelhttp.DefaultClient))
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
