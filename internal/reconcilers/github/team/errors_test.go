package github_team_reconciler

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v50/github"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGitHubValidationErrorDetails(t *testing.T) {
	for _, operation := range []string{"team update", "IDP sync"} {
		for _, parsed := range []bool{false, true} {
			name := operation + "/response body"
			if parsed {
				name = operation + "/parsed API error"
			}
			t.Run(name, func(t *testing.T) {
				ctx := t.Context()
				teams := NewMockTeamsService(t)
				r := &githubTeamReconciler{org: "org", teamsService: teams}
				req, err := http.NewRequestWithContext(ctx, http.MethodPatch, "https://api.github.com/orgs/org/teams/team", nil)
				require.NoError(t, err)
				resp := &github.Response{Response: &http.Response{
					Request:    req,
					StatusCode: http.StatusUnprocessableEntity,
					Status:     "422 Unprocessable Entity",
					Body:       io.NopCloser(strings.NewReader(`{"message":"Validation Failed","errors":[{"field":"parent_team_id","code":"invalid"}]}`)),
				}}
				var apiErr error
				if parsed {
					apiErr = &github.ErrorResponse{
						Response: resp.Response,
						Message:  "Validation Failed",
						Errors:   []github.Error{{Resource: "Team", Field: "parent_team_id", Code: "invalid"}},
					}
				}
				if operation == "team update" {
					teams.EXPECT().EditTeamBySlug(ctx, "org", "team", mock.Anything, false).
						Return(nil, resp, apiErr).Once()
					err = r.syncTeamInfo(ctx, &protoapi.Team{Slug: "team"}, &github.Team{Slug: new("team")}, 123)
					require.ErrorContains(t, err, `sync team info for GitHub team "team"`)
				} else {
					teams.EXPECT().CreateOrUpdateIDPGroupConnectionsBySlug(ctx, "org", "team", mock.Anything).
						Return(nil, resp, apiErr).Once()
					err = r.removeTeamIDPSync(ctx, "team")
					require.ErrorContains(t, err, `delete IDP sync from GitHub team "team"`)
				}
				require.ErrorContains(t, err, "Validation Failed")
				require.ErrorContains(t, err, "parent_team_id")
				if parsed {
					require.ErrorIs(t, err, apiErr)
				}
			})
		}
	}
}
