package github_team_reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/go-github/v50/github"
	"golang.org/x/oauth2"
)

type gitHubAuthTokenSource struct {
	ctx                context.Context
	googleTokenSource  oauth2.TokenSource
	gitHubAuthEndpoint string
}

func (ts *gitHubAuthTokenSource) Token() (*oauth2.Token, error) {
	client := oauth2.NewClient(ts.ctx, ts.googleTokenSource)
	resp, err := client.Get(ts.gitHubAuthEndpoint + "/createInstallationToken")
	if err != nil {
		return nil, fmt.Errorf("request GitHub installation token from auth service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Do not include the response body: it may contain credentials.
		return nil, fmt.Errorf("request GitHub installation token from auth service: unexpected HTTP status %s", resp.Status)
	}

	installationToken := &github.InstallationToken{}
	err = json.NewDecoder(resp.Body).Decode(installationToken)
	if err != nil {
		return nil, fmt.Errorf("decode GitHub installation token from auth service: %w", err)
	}
	if installationToken.GetToken() == "" {
		return nil, fmt.Errorf("GitHub auth service returned an empty installation token")
	}

	return &oauth2.Token{
		AccessToken: installationToken.GetToken(),
		Expiry:      installationToken.GetExpiresAt().Time,
	}, nil
}

func NewGitHubAuthClient(ctx context.Context, authEndpoint string, tokenSource oauth2.TokenSource) *http.Client {
	return oauth2.NewClient(ctx, &gitHubAuthTokenSource{
		ctx:                ctx,
		googleTokenSource:  tokenSource,
		gitHubAuthEndpoint: authEndpoint,
	})
}
