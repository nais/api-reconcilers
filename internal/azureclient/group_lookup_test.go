package azureclient_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/nais/api-reconcilers/internal/azureclient"
	"github.com/nais/api-reconcilers/internal/test"
	"github.com/stretchr/testify/require"
)

func TestGetGroupByMailNickname(t *testing.T) {
	const nextURL = "https://graph.microsoft.com/v1.0/groups?$skiptoken=opaque%2Btoken"
	for _, tt := range []struct {
		name     string
		response *http.Response
		wantID   string
		wantErr  string
	}{
		{name: "not found", response: test.Response("200 OK", `{"value":[]}`)},
		{name: "found", response: test.Response("200 OK", `{"value":[{"id":"parent-id"}]}`), wantID: "parent-id"},
		{name: "empty next link", response: test.Response("200 OK", `{"value":[{"id":"parent-id"}],"@odata.nextLink":""}`), wantID: "parent-id"},
		{name: "duplicate", response: test.Response("200 OK", `{"value":[{"id":"one"},{"id":"two"}]}`), wantErr: "multiple Azure groups"},
		{name: "next link with no matches", response: test.Response("200 OK", fmt.Sprintf(`{"value":[],"@odata.nextLink":%q}`, nextURL)), wantErr: "cannot confirm unique Azure group"},
		{name: "next link with one match", response: test.Response("200 OK", fmt.Sprintf(`{"value":[{"id":"one"}],"@odata.nextLink":%q}`, nextURL)), wantErr: "cannot confirm unique Azure group"},
		{name: "next link with two matches", response: test.Response("200 OK", fmt.Sprintf(`{"value":[{"id":"one"},{"id":"two"}],"@odata.nextLink":%q}`, nextURL)), wantErr: "cannot confirm unique Azure group"},
		{name: "forbidden", response: test.Response("403 Forbidden", `{"error":"denied"}`), wantErr: "403 Forbidden"},
		{name: "invalid response", response: test.Response("200 OK", `invalid`), wantErr: "invalid character"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			body := &trackedResponseBody{ReadCloser: tt.response.Body}
			tt.response.Body = body
			requests := 0
			client := azureclient.New(test.NewTestHttpClient(func(req *http.Request) *http.Response {
				requests++
				require.Equal(t, http.MethodGet, req.Method)
				require.Equal(t, ctx, req.Context())
				require.Equal(t, "/v1.0/groups", req.URL.Path)
				require.Equal(t, "mailNickname eq 'nais-teams''test'", req.URL.Query().Get("$filter"))
				require.Equal(t, "2", req.URL.Query().Get("$top"))
				return tt.response
			}))
			group, err := client.GetGroupByMailNickname(ctx, "nais-teams'test")
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.Nil(t, group)
			} else {
				require.NoError(t, err)
				if tt.wantID == "" {
					require.Nil(t, group)
				} else {
					require.Equal(t, tt.wantID, group.ID)
				}
			}
			require.Equal(t, 1, requests)
			require.True(t, body.closed)
		})
	}
}
