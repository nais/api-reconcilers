package azureclient_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nais/api-reconcilers/internal/azureclient"
	"github.com/nais/api-reconcilers/internal/test"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/stretchr/testify/require"
)

func Test_GetUser(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		if expected := "https://graph.microsoft.com/v1.0/users/user@example.com"; req.URL.String() != expected {
			t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
		}

		if expected := http.MethodGet; req.Method != expected {
			t.Errorf("Expected method %q, got %q", expected, req.Method)
		}

		return test.Response("200 OK", `{
			"mail": "user@example.com",
			"id": "some-id"
		}`)
	})

	client := azureclient.New(httpClient)
	member, err := client.GetUser(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if expected := "user@example.com"; member.Mail != expected {
		t.Errorf("Expected mail %q, got %q", expected, member.Mail)
	}

	if expected := "some-id"; member.ID != expected {
		t.Errorf("Expected ID %q, got %q", expected, member.ID)
	}
}

func Test_GetUserThatDoesNotExist(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		if expected := "https://graph.microsoft.com/v1.0/users/user@example.com"; req.URL.String() != expected {
			t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
		}

		if expected := http.MethodGet; req.Method != expected {
			t.Errorf("Expected method %q, got %q", expected, req.Method)
		}

		return test.Response("404 Not Found", `{"error": {"message": "user does not exist"}}`)
	})

	client := azureclient.New(httpClient)
	member, err := client.GetUser(context.Background(), "user@example.com")

	if member != nil {
		t.Errorf("Expected no member, got %v", member)
	}

	if expected := `404 Not Found: {"error": {"message": "user does not exist"}}`; err.Error() != expected {
		t.Errorf("Expected error %q, got %q", expected, err)
	}
}

func Test_GetUserWithInvalidApiResponse(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		if expected := "https://graph.microsoft.com/v1.0/users/user@example.com"; req.URL.String() != expected {
			t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
		}

		if expected := http.MethodGet; req.Method != expected {
			t.Errorf("Expected method %q, got %q", expected, req.Method)
		}

		return test.Response("200 OK", "some string")
	})

	client := azureclient.New(httpClient)
	member, err := client.GetUser(context.Background(), "user@example.com")

	if member != nil {
		t.Errorf("Expected no member, got %v", member)
	}

	if expected := "invalid character 's' looking for beginning of value"; err.Error() != expected {
		t.Errorf("Expected error %q, got %q", expected, err)
	}
}

func Test_GetGroupById(t *testing.T) {
	groupId := uuid.New()
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		if expected := "https://graph.microsoft.com/v1.0/groups/" + groupId.String(); req.URL.String() != expected {
			t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
		}

		if expected := http.MethodGet; req.Method != expected {
			t.Errorf("Expected method %q, got %q", expected, req.Method)
		}

		return test.Response("200 OK", fmt.Sprintf(`{
			"id":"%s",
			"description":"description",
			"displayName": "name",
			"mailNickname": "mail"
		}`, groupId.String()))
	})

	client := azureclient.New(httpClient)
	group, err := client.GetGroupById(context.Background(), groupId)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if group.ID != groupId.String() {
		t.Errorf("Expected group ID %q, got %q", groupId.String(), group.ID)
	}
}

func Test_GetGroupThatDoesNotExist(t *testing.T) {
	groupId := uuid.New()
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		if expected := "https://graph.microsoft.com/v1.0/groups/" + groupId.String(); req.URL.String() != expected {
			t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
		}

		if expected := http.MethodGet; req.Method != expected {
			t.Errorf("Expected method %q, got %q", expected, req.Method)
		}
		return test.Response("404 Not Found", "{}")
	})

	client := azureclient.New(httpClient)
	group, err := client.GetGroupById(context.Background(), groupId)

	if group != nil {
		t.Errorf("Expected no group, got %v", group)
	}

	if contains := "azure group with ID"; !strings.Contains(err.Error(), contains) {
		t.Errorf("Expected error to contain %q, got %q", contains, err)
	}
}

func TestGetGroupByUniqueName(t *testing.T) {
	for _, tt := range []struct {
		name     string
		response *http.Response
		wantID   string
		wantErr  string
	}{
		{name: "found", response: test.Response("200 OK", `{"id":"parent-id"}`), wantID: "parent-id"},
		{name: "not found", response: test.Response("404 Not Found", `{}`)},
		{name: "forbidden is not treated as missing", response: test.Response("403 Forbidden", `{"error":"denied"}`), wantErr: "403 Forbidden"},
		{name: "server error is not treated as missing", response: test.Response("500 Internal Server Error", `{"error":"failed"}`), wantErr: "500 Internal Server Error"},
		{name: "invalid JSON", response: test.Response("200 OK", `invalid`), wantErr: "invalid character"},
		{name: "missing ID", response: test.Response("200 OK", `{}`), wantErr: "no ID returned"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			body := &trackedResponseBody{ReadCloser: tt.response.Body}
			tt.response.Body = body
			client := azureclient.New(test.NewTestHttpClient(func(req *http.Request) *http.Response {
				require.Equal(t, http.MethodGet, req.Method)
				require.Equal(t, ctx, req.Context())
				require.Equal(t, "/v1.0/groups(uniqueName='nais-teams%27%27test%2Fchild')", req.URL.EscapedPath())
				require.Equal(t, "id", req.URL.Query().Get("$select"))
				return tt.response
			}))
			group, err := client.GetGroupByUniqueName(ctx, "nais-teams'test/child")
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
			require.True(t, body.closed)
		})
	}
}

func TestUpsertGroupByUniqueName(t *testing.T) {
	for _, tt := range []struct {
		name      string
		responses []*http.Response
		wantID    string
		wantErr   string
	}{
		{
			name:      "created ID is used without another read",
			responses: []*http.Response{test.Response("201 Created", `{"id":"parent-id","securityEnabled":true}`)},
			wantID:    "parent-id",
		},
		{
			name: "stale lookup is resolved by server-side alternate key",
			responses: []*http.Response{
				test.Response("204 No Content", ""),
				test.Response("200 OK", `{"id":"existing-id"}`),
			},
			wantID: "existing-id",
		},
		{
			name:      "stale read after update causes retry not unkeyed creation",
			responses: []*http.Response{test.Response("204 No Content", ""), test.Response("404 Not Found", `{}`)},
			wantErr:   "not yet visible after upsert",
		},
		{
			name:      "read failure after update",
			responses: []*http.Response{test.Response("204 No Content", ""), test.Response("503 Service Unavailable", `{"error":"unavailable"}`)},
			wantErr:   "503 Service Unavailable",
		},
		{
			name:      "creation conflict is propagated for retry",
			responses: []*http.Response{test.Response("409 Conflict", `{"error":"conflict"}`)},
			wantErr:   "409 Conflict",
		},
		{
			name:      "permission denied",
			responses: []*http.Response{test.Response("403 Forbidden", `{"error":"denied"}`)},
			wantErr:   "403 Forbidden",
		},
		{
			name:      "invalid creation response",
			responses: []*http.Response{test.Response("201 Created", `invalid`)},
			wantErr:   "invalid character",
		},
		{
			name:      "missing created ID",
			responses: []*http.Response{test.Response("201 Created", `{}`)},
			wantErr:   "no ID returned",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			input := &azureclient.Group{
				Description: "Parent group for all teams synced by Nais.", DisplayName: "nais-teams",
				MailNickname: "nais-teams", SecurityEnabled: true,
			}
			var handlers []test.RoundTripFunc
			var bodies []*trackedResponseBody
			requests := 0
			for i, response := range tt.responses {
				body := &trackedResponseBody{ReadCloser: response.Body}
				response.Body = body
				bodies = append(bodies, body)
				handlers = append(handlers, func(req *http.Request) *http.Response {
					requests++
					require.Equal(t, ctx, req.Context())
					require.Equal(t, "/v1.0/groups(uniqueName='nais-teams%27%27test%2Fchild')", req.URL.EscapedPath())
					if i == 0 {
						require.Equal(t, http.MethodPatch, req.Method)
						require.Equal(t, "application/json", req.Header.Get("Content-Type"))
						require.Equal(t, "create-if-missing", req.Header.Get("Prefer"))
						var payload map[string]any
						require.NoError(t, json.NewDecoder(req.Body).Decode(&payload))
						require.Equal(t, map[string]any{
							"description": input.Description, "displayName": "nais-teams", "mailNickname": "nais-teams",
							"mailEnabled": false, "securityEnabled": true,
						}, payload)
					} else {
						require.Equal(t, http.MethodGet, req.Method)
						require.Equal(t, "id", req.URL.Query().Get("$select"))
					}
					return response
				})
			}
			client := azureclient.New(test.NewTestHttpClient(handlers...))
			group, err := client.UpsertGroupByUniqueName(ctx, "nais-teams'test/child", input)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.Nil(t, group)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantID, group.ID)
			}
			require.Equal(t, len(tt.responses), requests)
			for _, body := range bodies {
				require.True(t, body.closed)
			}
		})
	}
}

func Test_CreateGroup(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		if expected := "https://graph.microsoft.com/v1.0/groups"; req.URL.String() != expected {
			t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
		}

		if expected := http.MethodPost; req.Method != expected {
			t.Errorf("Expected method %q, got %q", expected, req.Method)
		}

		if expected := "application/json"; req.Header.Get("content-type") != expected {
			t.Errorf("Expected content-type %q, got %q", expected, req.Header.Get("content-type"))
		}

		return test.Response("201 Created", `{
			"id":"some-id",
			"description":"description",
			"displayName": "name",
			"mailNickname": "mail"
		}`)
	})

	client := azureclient.New(httpClient)
	input := &azureclient.Group{
		Description:  "description",
		DisplayName:  "name",
		MailNickname: "mail",
	}
	expectedOutput := input
	expectedOutput.ID = "some-id"

	group, err := client.CreateGroup(context.Background(), input)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if expectedOutput.ID != group.ID {
		t.Errorf("Expected group %v, got %v", expectedOutput, group)
	}
}

func Test_CreateGroupWithInvalidStatus(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		if expected := "https://graph.microsoft.com/v1.0/groups"; req.URL.String() != expected {
			t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
		}

		if expected := http.MethodPost; req.Method != expected {
			t.Errorf("Expected method %q, got %q", expected, req.Method)
		}

		if expected := "application/json"; req.Header.Get("content-type") != expected {
			t.Errorf("Expected content-type %q, got %q", expected, req.Header.Get("content-type"))
		}

		return test.Response("400 Bad Request", `{"error": {"message":"some error"}}`)
	})

	client := azureclient.New(httpClient)

	group, err := client.CreateGroup(context.Background(), &azureclient.Group{
		Description:  "description",
		DisplayName:  "name",
		MailNickname: "mail",
	})

	if group != nil {
		t.Errorf("Expected no group, got %v", group)
	}

	if expected := `create azure group "mail": 400 Bad Request: {"error": {"message":"some error"}}`; err.Error() != expected {
		t.Errorf("Expected error %q, got %q", expected, err)
	}
}

func Test_CreateGroupWithInvalidResponse(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		if expected := "https://graph.microsoft.com/v1.0/groups"; req.URL.String() != expected {
			t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
		}

		if expected := http.MethodPost; req.Method != expected {
			t.Errorf("Expected method %q, got %q", expected, req.Method)
		}

		if expected := "application/json"; req.Header.Get("content-type") != expected {
			t.Errorf("Expected content-type %q, got %q", expected, req.Header.Get("content-type"))
		}

		return test.Response("201 Created", "response body")
	})

	client := azureclient.New(httpClient)

	group, err := client.CreateGroup(context.Background(), &azureclient.Group{
		Description:  "description",
		DisplayName:  "name",
		MailNickname: "mail",
	})

	if group != nil {
		t.Errorf("Expected no group, got %v", group)
	}

	if expected := "invalid character 'r' looking for beginning of value"; err.Error() != expected {
		t.Errorf("Expected error %q, got %q", expected, err)
	}
}

func Test_CreateGroupWithIncompleteResponse(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		if expected := "https://graph.microsoft.com/v1.0/groups"; req.URL.String() != expected {
			t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
		}

		if expected := http.MethodPost; req.Method != expected {
			t.Errorf("Expected method %q, got %q", expected, req.Method)
		}

		if expected := "application/json"; req.Header.Get("content-type") != expected {
			t.Errorf("Expected content-type %q, got %q", expected, req.Header.Get("content-type"))
		}

		return test.Response("201 Created", `{
			"description":"description",
			"displayName": "name",
			"mailNickname": "mail"
		}`)
	})

	client := azureclient.New(httpClient)

	group, err := client.CreateGroup(context.Background(), &azureclient.Group{
		Description:  "description",
		DisplayName:  "name",
		MailNickname: "mail",
	})

	if expected := `azure group "mail" created, but no ID returned`; err.Error() != expected {
		t.Errorf("Expected error %q, got %q", expected, err)
	}

	if group != nil {
		t.Errorf("Expected no group, got %v", group)
	}
}

func Test_GetOrCreateGroupWithNoExistingGroupID(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			if expected := "https://graph.microsoft.com/v1.0/groups"; req.URL.String() != expected {
				t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
			}

			if expected := http.MethodPost; req.Method != expected {
				t.Errorf("Expected method %q, got %q", expected, req.Method)
			}

			if expected := "application/json"; req.Header.Get("content-type") != expected {
				t.Errorf("Expected content-type %q, got %q", expected, req.Header.Get("content-type"))
			}

			return test.Response("201 Created", `{
				"id":"group-id",
				"description":"description",
				"displayName": "name",
				"mailNickname": "mail"
			}`)
		},
	)

	team := &protoapi.Team{
		Slug:    "slug",
		Purpose: "description",
	}

	client := azureclient.New(httpClient)
	group, created, err := client.GetOrCreateGroup(context.Background(), team, "slug")
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}

	if group.ID != "group-id" {
		t.Errorf("Expected group id %s, got %s", "group-id", group.ID)
	}

	if !created {
		t.Errorf("Expected group to be created")
	}
}

func Test_GetOrCreateGroupWhenGroupInStateDoesNotExist(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			return test.Response("404 Not Found", "{}")
		},
		func(req *http.Request) *http.Response {
			return test.Response("201 Created", `{
				"id":"some-id",
				"description":"description",
				"displayName": "name",
				"mailNickname": "mail"
			}`)
		},
	)

	team := &protoapi.Team{
		Slug:           "slug",
		Purpose:        "description",
		EntraIdGroupId: new(uuid.New().String()),
	}

	client := azureclient.New(httpClient)
	group, created, err := client.GetOrCreateGroup(context.Background(), team, "slug")

	if group != nil {
		t.Errorf("Expected no group, got %v", group)
	}

	if created {
		t.Errorf("Expected group to not be created")
	}

	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}

func Test_GetOrCreateGroupWhenGroupInStateExists(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			return test.Response("200 OK", `{
					"id":"some-id",
					"description":"description",
					"displayName": "name",
					"mailNickname": "mail"
				}`)
		},
		func(req *http.Request) *http.Response {
			return nil
		},
	)

	team := &protoapi.Team{
		Slug:           "slug",
		Purpose:        "description",
		EntraIdGroupId: new(uuid.New().String()),
	}

	client := azureclient.New(httpClient)
	group, created, err := client.GetOrCreateGroup(context.Background(), team, "slug")
	if err != nil {
		t.Errorf("Expected no error, got %s", err)
	}

	if group.ID != "some-id" {
		t.Errorf("Expected group id %s, got %s", "some-id", group.ID)
	}

	if group.Description != "description" {
		t.Errorf("Expected group description %s, got %s", "description", group.Description)
	}

	if group.DisplayName != "name" {
		t.Errorf("Expected group display name %s, got %s", "name", group.DisplayName)
	}

	if group.MailNickname != "mail" {
		t.Errorf("Expected group mail nickname %s, got %s", "mail", group.MailNickname)
	}

	if created {
		t.Errorf("Expected group to not be created")
	}
}

func Test_ListGroupMembers(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			if expected := "https://graph.microsoft.com/v1.0/groups/group-id/members"; req.URL.String() != expected {
				t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
			}

			if expected := http.MethodGet; req.Method != expected {
				t.Errorf("Expected method %q, got %q", expected, req.Method)
			}

			return test.Response("200 OK", `{
				"value": [
					{"id": "user-id-1"},
					{"id": "user-id-2"}
				]
			}`)
		},
	)

	client := azureclient.New(httpClient)

	members, err := client.ListGroupMembers(context.Background(), &azureclient.Group{
		ID: "group-id",
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(members) != 2 {
		t.Fatalf("Expected 2 members, got %v", members)
	}

	if expected := "user-id-1"; members[0].ID != expected {
		t.Errorf("Expected member ID %q, got %q", expected, members[0].ID)
	}

	if expected := "user-id-2"; members[1].ID != expected {
		t.Errorf("Expected member ID %q, got %q", expected, members[1].ID)
	}
}

func Test_ListGroupMembersWhenGroupDoesNotExist(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			if expected := "https://graph.microsoft.com/v1.0/groups/group-id/members"; req.URL.String() != expected {
				t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
			}

			if expected := http.MethodGet; req.Method != expected {
				t.Errorf("Expected method %q, got %q", expected, req.Method)
			}

			return test.Response("404 Not Found", `{"error":{"message":"some error"}}`)
		},
	)

	client := azureclient.New(httpClient)

	members, err := client.ListGroupMembers(context.Background(), &azureclient.Group{
		ID:           "group-id",
		MailNickname: "mail",
	})

	if expected := `list group members "mail": 404 Not Found: {"error":{"message":"some error"}}`; err.Error() != expected {
		t.Errorf("Expected error %q, got %q", expected, err)
	}

	if len(members) != 0 {
		t.Errorf("Expected no members, got %v", members)
	}
}

func Test_ListGroupMembersWithInvalidResponse(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			if expected := "https://graph.microsoft.com/v1.0/groups/group-id/members"; req.URL.String() != expected {
				t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
			}

			if expected := http.MethodGet; req.Method != expected {
				t.Errorf("Expected method %q, got %q", expected, req.Method)
			}

			return test.Response("200 OK", "some response")
		},
	)

	client := azureclient.New(httpClient)

	members, err := client.ListGroupMembers(context.Background(), &azureclient.Group{
		ID: "group-id",
	})

	if expected := "invalid character 's' looking for beginning of value"; err.Error() != expected {
		t.Errorf("Expected error %q, got %q", expected, err)
	}

	if members != nil {
		t.Errorf("Expected no members, got %v", members)
	}
}

func Test_AddMemberToGroup(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			if expected := "https://graph.microsoft.com/v1.0/groups/group-id/members/$ref"; req.URL.String() != expected {
				t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
			}

			if expected := http.MethodPost; req.Method != expected {
				t.Errorf("Expected method %q, got %q", expected, req.Method)
			}

			if expected := "application/json"; req.Header.Get("content-type") != expected {
				t.Errorf("Expected content-type %q, got %q", expected, req.Header.Get("content-type"))
			}

			body, _ := io.ReadAll(req.Body)
			if expected := `{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/user-id"}`; string(body) != expected {
				t.Errorf("Expected body %q, got %q", expected, string(body))
			}

			return test.Response("204 No Content", "")
		},
	)

	client := azureclient.New(httpClient)

	err := client.AddMemberToGroup(context.Background(), &azureclient.Group{
		ID: "group-id",
	}, &azureclient.Member{
		ID:   "user-id",
		Mail: "mail@example.com",
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func Test_AddMemberToGroupWithInvalidResponse(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			if expected := "https://graph.microsoft.com/v1.0/groups/group-id/members/$ref"; req.URL.String() != expected {
				t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
			}

			if expected := http.MethodPost; req.Method != expected {
				t.Errorf("Expected method %q, got %q", expected, req.Method)
			}

			if expected := "application/json"; req.Header.Get("content-type") != expected {
				t.Errorf("Expected content-type %q, got %q", expected, req.Header.Get("content-type"))
			}

			return test.Response("200 OK", "some response body")
		},
	)

	client := azureclient.New(httpClient)

	err := client.AddMemberToGroup(context.Background(), &azureclient.Group{
		ID:           "group-id",
		MailNickname: "group",
	}, &azureclient.Member{
		ID:   "user-id",
		Mail: "mail@example.com",
	})

	if expected := `add member "mail@example.com" to azure group "group": 200 OK: some response body`; err.Error() != expected {
		t.Errorf("Expected error %q, got %q", expected, err)
	}
}

func Test_RemoveMemberFromGroup(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			if expected := "https://graph.microsoft.com/v1.0/groups/group-id/members/user-id/$ref"; req.URL.String() != expected {
				t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
			}

			if expected := http.MethodDelete; req.Method != expected {
				t.Errorf("Expected method %q, got %q", expected, req.Method)
			}

			return test.Response("204 No Content", "")
		},
	)

	client := azureclient.New(httpClient)

	err := client.RemoveMemberFromGroup(context.Background(), &azureclient.Group{
		ID: "group-id",
	}, &azureclient.Member{
		ID: "user-id",
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func Test_RemoveMemberFromGroupWithInvalidResponse(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			if expected := "https://graph.microsoft.com/v1.0/groups/group-id/members/user-id/$ref"; req.URL.String() != expected {
				t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
			}

			if expected := http.MethodDelete; req.Method != expected {
				t.Errorf("Expected method %q, got %q", expected, req.Method)
			}

			return test.Response("200 OK", "some response body")
		},
	)

	client := azureclient.New(httpClient)

	err := client.RemoveMemberFromGroup(context.Background(), &azureclient.Group{
		ID:           "group-id",
		MailNickname: "mail@example.com",
	}, &azureclient.Member{
		ID:   "user-id",
		Mail: "mail",
	})

	if expected := `remove member "mail" from azure group "mail@example.com": 200 OK: some response body`; err.Error() != expected {
		t.Errorf("Expected error %q, got %q", expected, err)
	}
}

func Test_DeleteGroup(t *testing.T) {
	ctx := context.Background()
	grpID := uuid.New()

	t.Run("Successful delete", func(t *testing.T) {
		httpClient := test.NewTestHttpClient(
			func(req *http.Request) *http.Response {
				if expected := "https://graph.microsoft.com/v1.0/groups/" + grpID.String(); req.URL.String() != expected {
					t.Errorf("Expected URL %q, got %q", expected, req.URL.String())
				}
				if expected := http.MethodDelete; req.Method != expected {
					t.Errorf("Expected method %q, got %q", expected, req.Method)
				}

				if req.Context() != ctx {
					t.Errorf("Expected context %v, got %v", ctx, req.Context())
				}
				return test.Response("204 No Content", "some response body")
			},
		)

		client := azureclient.New(httpClient)
		err := client.DeleteGroup(ctx, grpID)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
	})

	t.Run("Delete error", func(t *testing.T) {
		httpClient := test.NewTestHttpClient(
			func(req *http.Request) *http.Response {
				return test.Response("200 OK", "some response body")
			},
		)

		client := azureclient.New(httpClient)
		err := client.DeleteGroup(ctx, grpID)

		if contains := "remove azure group with ID"; !strings.Contains(err.Error(), contains) {
			t.Errorf("Expected error to contain %q, got %q", contains, err)
		}

		if contains := grpID.String(); !strings.Contains(err.Error(), contains) {
			t.Errorf("Expected error to contain %q, got %q", contains, err)
		}
	})

	t.Run("404 is considered OK", func(t *testing.T) {
		httpClient := test.NewTestHttpClient(
			func(req *http.Request) *http.Response {
				return test.Response("404 Not Found", "{}")
			},
		)

		client := azureclient.New(httpClient)
		err := client.DeleteGroup(ctx, grpID)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
	})
}
