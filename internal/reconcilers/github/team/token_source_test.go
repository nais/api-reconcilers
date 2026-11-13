package github_team_reconciler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nais/api-reconcilers/internal/test"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGitHubAuthTokenSource(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status string
		body   string
		err    string
	}{
		{
			name: "success", status: "200 OK",
			body: `{"token":"secret-installation-token","expires_at":"2030-01-01T00:00:00Z"}`,
		},
		{
			name: "plain text not found", status: "404 Not Found", body: "not found",
			err: "request GitHub installation token from auth service: unexpected HTTP status 404 Not Found",
		},
		{
			name: "server error with sensitive body", status: "500 Internal Server Error",
			body: `{"token":"secret-installation-token"}`,
			err:  "unexpected HTTP status 500 Internal Server Error",
		},
		{
			name: "malformed JSON", status: "200 OK", body: "not found",
			err: "decode GitHub installation token from auth service",
		},
		{
			name: "empty response", status: "200 OK",
			err: "decode GitHub installation token from auth service",
		},
		{
			name: "missing token", status: "200 OK", body: `{}`,
			err: "GitHub auth service returned an empty installation token",
		},
		{
			name: "empty token", status: "200 OK", body: `{"token":""}`,
			err: "GitHub auth service returned an empty installation token",
		},
		{
			name: "null response", status: "200 OK", body: `null`,
			err: "GitHub auth service returned an empty installation token",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := &tokenResponseBody{Reader: strings.NewReader(tt.body)}
			client := test.NewTestHttpClient(func(req *http.Request) *http.Response {
				require.Equal(t, http.MethodGet, req.Method)
				require.Equal(t, "https://github-auth.example/createInstallationToken", req.URL.String())
				require.Equal(t, "Bearer google-token", req.Header.Get("Authorization"))
				resp := test.Response(tt.status, "")
				resp.Body = body
				return resp
			})
			ts := &gitHubAuthTokenSource{
				ctx:                context.WithValue(t.Context(), oauth2.HTTPClient, client),
				googleTokenSource:  oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "google-token"}),
				gitHubAuthEndpoint: "https://github-auth.example",
			}

			token, err := ts.Token()
			require.True(t, body.closed, "response body must be closed on success and failure")
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				require.NotContains(t, err.Error(), "secret-installation-token")
				require.Nil(t, token)
				if tt.name == "malformed JSON" {
					var syntaxErr *json.SyntaxError
					require.ErrorAs(t, err, &syntaxErr)
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, "secret-installation-token", token.AccessToken)
			require.Equal(t, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), token.Expiry)
		})
	}
}

func TestGitHubAuthTokenSourceRequestFailure(t *testing.T) {
	ts := &gitHubAuthTokenSource{
		ctx:                t.Context(),
		googleTokenSource:  oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "google-token"}),
		gitHubAuthEndpoint: ":invalid-url",
	}

	token, err := ts.Token()
	require.Nil(t, token)
	require.ErrorContains(t, err, "request GitHub installation token from auth service")
	var urlErr *url.Error
	require.ErrorAs(t, err, &urlErr)
}

type tokenResponseBody struct {
	io.Reader
	closed bool
}

func (b *tokenResponseBody) Close() error {
	b.closed = true
	return nil
}
