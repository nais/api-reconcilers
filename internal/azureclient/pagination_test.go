package azureclient_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/nais/api-reconcilers/internal/azureclient"
	"github.com/nais/api-reconcilers/internal/test"
)

func Test_ListGroupMembersAndOwnersPagination(t *testing.T) {
	for _, relationship := range []string{"members", "owners"} {
		t.Run(relationship, func(t *testing.T) {
			baseURL := "https://graph.microsoft.com/v1.0/groups/group-id/" + relationship
			// The next link is opaque: preserve its query parameters and encoded token.
			nextURL := baseURL + "?$top=1&$skiptoken=opaque%2Btoken%2F%3D"
			lastURL := baseURL + "?$skiptoken=last-page"
			for _, tt := range []struct {
				name        string
				urls        []string
				responses   []*http.Response
				expected    []string
				expectedErr string
			}{
				{
					name:      "empty collection",
					urls:      []string{baseURL},
					responses: []*http.Response{test.Response("200 OK", `{"value":[]}`)},
				},
				{
					name:      "single page with empty next link",
					urls:      []string{baseURL},
					responses: []*http.Response{test.Response("200 OK", `{"value":[{"id":"user-1"}],"@odata.nextLink":""}`)},
					expected:  []string{"user-1"},
				},
				{
					name: "multiple pages including an empty intermediate page",
					urls: []string{baseURL, nextURL, lastURL},
					responses: []*http.Response{
						test.Response("200 OK", fmt.Sprintf(`{"value":[{"id":"user-1"}],"@odata.nextLink":%q}`, nextURL)),
						test.Response("200 OK", fmt.Sprintf(`{"value":[],"@odata.nextLink":%q}`, lastURL)),
						test.Response("200 OK", `{"value":[{"id":"user-2"},{"id":"user-3"}]}`),
					},
					expected: []string{"user-1", "user-2", "user-3"},
				},
				{
					name:        "first page HTTP error",
					urls:        []string{baseURL},
					responses:   []*http.Response{test.Response("403 Forbidden", `{"error":"denied"}`)},
					expectedErr: fmt.Sprintf(`list group %s "mail": 403 Forbidden: {"error":"denied"}`, relationship),
				},
				{
					name: "later page HTTP error",
					urls: []string{baseURL, nextURL},
					responses: []*http.Response{
						test.Response("200 OK", fmt.Sprintf(`{"value":[{"id":"user-1"}],"@odata.nextLink":%q}`, nextURL)),
						test.Response("500 Internal Server Error", `{"error":"failed"}`),
					},
					expectedErr: fmt.Sprintf(`list group %s "mail": 500 Internal Server Error: {"error":"failed"}`, relationship),
				},
				{
					name: "later page invalid JSON",
					urls: []string{baseURL, nextURL},
					responses: []*http.Response{
						test.Response("200 OK", fmt.Sprintf(`{"value":[{"id":"user-1"}],"@odata.nextLink":%q}`, nextURL)),
						test.Response("200 OK", "invalid"),
					},
					expectedErr: "invalid character 'i' looking for beginning of value",
				},
			} {
				t.Run(tt.name, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					var bodies []*trackedResponseBody
					var handlers []test.RoundTripFunc
					for i, response := range tt.responses {
						body := &trackedResponseBody{ReadCloser: response.Body}
						response.Body = body
						bodies = append(bodies, body)
						handlers = append(handlers, func(req *http.Request) *http.Response {
							if req.URL.String() != tt.urls[i] {
								t.Errorf("Expected URL %q, got %q", tt.urls[i], req.URL.String())
							}
							if req.Method != http.MethodGet {
								t.Errorf("Expected GET, got %q", req.Method)
							}
							if req.Context() != ctx {
								t.Error("Expected request to use caller context")
							}
							if i > 0 && !bodies[i-1].closed {
								t.Error("Expected previous response body to be closed before fetching next page")
							}
							return response
						})
					}
					client := azureclient.New(test.NewTestHttpClient(handlers...))
					list := client.ListGroupMembers
					if relationship == "owners" {
						list = client.ListGroupOwners
					}
					members, err := list(ctx, &azureclient.Group{ID: "group-id", MailNickname: "mail"})
					if tt.expectedErr != "" {
						if err == nil || err.Error() != tt.expectedErr {
							t.Fatalf("Expected error %q, got %v", tt.expectedErr, err)
						}
						if members != nil {
							t.Errorf("Expected no partial results, got %v", members)
						}
					} else if err != nil {
						t.Fatalf("Expected no error, got %v", err)
					}
					var ids []string
					for _, member := range members {
						ids = append(ids, member.ID)
					}
					if !slices.Equal(ids, tt.expected) {
						t.Errorf("Expected member IDs %v, got %v", tt.expected, ids)
					}
					for i, body := range bodies {
						if !body.closed {
							t.Errorf("Expected response body for page %d to be closed", i+1)
						}
					}
				})
			}
		})
	}
}

type trackedResponseBody struct {
	io.ReadCloser
	closed bool
}

func (b *trackedResponseBody) Close() error {
	b.closed = true
	return b.ReadCloser.Close()
}
