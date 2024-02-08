package azureclient_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/nais/api-reconcilers/internal/azureclient"
	"github.com/nais/api-reconcilers/internal/test"
	"github.com/nais/api/pkg/protoapi"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"
)

func Test_GetUser(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		assert.Equal(t, "https://graph.microsoft.com/v1.0/users/user@example.com", req.URL.String())
		assert.Equal(t, http.MethodGet, req.Method)

		return test.Response("200 OK", `{
			"mail": "user@example.com",
			"id": "some-id"
		}`)
	})

	client := azureclient.New(httpClient)
	member, err := client.GetUser(context.Background(), "user@example.com")

	assert.Equal(t, "user@example.com", member.Mail)
	assert.Equal(t, "some-id", member.ID)
	assert.NoError(t, err)
}

func Test_GetUserThatDoesNotExist(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		assert.Equal(t, "https://graph.microsoft.com/v1.0/users/user@example.com", req.URL.String())
		assert.Equal(t, http.MethodGet, req.Method)

		return test.Response("404 Not Found", `{"error": {"message": "user does not exist"}}`)
	})

	client := azureclient.New(httpClient)
	member, err := client.GetUser(context.Background(), "user@example.com")

	assert.Nil(t, member)
	assert.EqualError(t, err, `404 Not Found: {"error": {"message": "user does not exist"}}`)
}

func Test_GetUserWithInvalidApiResponse(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		assert.Equal(t, "https://graph.microsoft.com/v1.0/users/user@example.com", req.URL.String())
		assert.Equal(t, http.MethodGet, req.Method)

		return test.Response("200 OK", "some string")
	})

	client := azureclient.New(httpClient)
	member, err := client.GetUser(context.Background(), "user@example.com")

	assert.Nil(t, member)
	assert.EqualError(t, err, "invalid character 's' looking for beginning of value")
}

func Test_GetGroupById(t *testing.T) {
	groupId := uuid.New()
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		assert.Equal(t, "https://graph.microsoft.com/v1.0/groups/"+groupId.String(), req.URL.String())
		assert.Equal(t, http.MethodGet, req.Method)
		return test.Response("200 OK", fmt.Sprintf(`{
			"id":"%s",
			"description":"description",
			"displayName": "name",
			"mailNickname": "mail"
		}`, groupId.String()))
	})

	client := azureclient.New(httpClient)
	group, err := client.GetGroupById(context.Background(), groupId)

	assert.NoError(t, err)
	assert.Equal(t, groupId.String(), group.ID)
}

func Test_GetGroupThatDoesNotExist(t *testing.T) {
	groupId := uuid.New()
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		assert.Equal(t, "https://graph.microsoft.com/v1.0/groups/"+groupId.String(), req.URL.String())
		assert.Equal(t, http.MethodGet, req.Method)
		return test.Response("404 Not Found", "{}")
	})

	client := azureclient.New(httpClient)
	group, err := client.GetGroupById(context.Background(), groupId)

	assert.Nil(t, group)
	assert.ErrorContains(t, err, "azure group with ID")
}

func Test_CreateGroup(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		assert.Equal(t, "https://graph.microsoft.com/v1.0/groups", req.URL.String())
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, "application/json", req.Header.Get("content-type"))

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

	assert.Equal(t, expectedOutput, group)
	assert.NoError(t, err)
}

func Test_CreateGroupWithInvalidStatus(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		assert.Equal(t, "https://graph.microsoft.com/v1.0/groups", req.URL.String())
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, "application/json", req.Header.Get("content-type"))

		return test.Response("400 Bad Request", `{"error": {"message":"some error"}}`)
	})

	client := azureclient.New(httpClient)

	group, err := client.CreateGroup(context.Background(), &azureclient.Group{
		Description:  "description",
		DisplayName:  "name",
		MailNickname: "mail",
	})

	assert.Nil(t, group)
	assert.EqualError(t, err, `create azure group "mail": 400 Bad Request: {"error": {"message":"some error"}}`)
}

func Test_CreateGroupWithInvalidResponse(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		assert.Equal(t, "https://graph.microsoft.com/v1.0/groups", req.URL.String())
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, "application/json", req.Header.Get("content-type"))

		return test.Response("201 Created", "response body")
	})

	client := azureclient.New(httpClient)

	group, err := client.CreateGroup(context.Background(), &azureclient.Group{
		Description:  "description",
		DisplayName:  "name",
		MailNickname: "mail",
	})

	assert.Nil(t, group)
	assert.EqualError(t, err, "invalid character 'r' looking for beginning of value")
}

func Test_CreateGroupWithIncompleteResponse(t *testing.T) {
	httpClient := test.NewTestHttpClient(func(req *http.Request) *http.Response {
		assert.Equal(t, "https://graph.microsoft.com/v1.0/groups", req.URL.String())
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, "application/json", req.Header.Get("content-type"))

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

	assert.Nil(t, group)
	assert.EqualError(t, err, `azure group "mail" created, but no ID returned`)
}

func Test_GetOrCreateGroupWithNoExistingGroupID(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			if req.URL.String() != "https://graph.microsoft.com/v1.0/groups" {
				t.Errorf("Expected URL %s, got %s", "https://graph.microsoft.com/v1.0/groups", req.URL.String())
			}

			if http.MethodPost != req.Method {
				t.Errorf("Expected method %s, got %s", http.MethodPost, req.Method)
			}

			if req.Header.Get("content-type") != "application/json" {
				t.Errorf("Expected content-type %s, got %s", "application/json", req.Header.Get("content-type"))
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
	groupId := uuid.New()
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
		Slug:         "slug",
		Purpose:      "description",
		AzureGroupId: ptr.To(groupId.String()),
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
	groupId := uuid.New()
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
		Slug:         "slug",
		Purpose:      "description",
		AzureGroupId: ptr.To(groupId.String()),
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
			assert.Equal(t, "https://graph.microsoft.com/v1.0/groups/group-id/members", req.URL.String())
			assert.Equal(t, http.MethodGet, req.Method)

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

	assert.NoError(t, err)
	assert.Len(t, members, 2)
	assert.Equal(t, "user-id-1", members[0].ID)
	assert.Equal(t, "user-id-2", members[1].ID)
}

func Test_ListGroupMembersWhenGroupDoesNotExist(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			assert.Equal(t, "https://graph.microsoft.com/v1.0/groups/group-id/members", req.URL.String())
			assert.Equal(t, http.MethodGet, req.Method)

			return test.Response("404 Not Found", `{"error":{"message":"some error"}}`)
		},
	)

	client := azureclient.New(httpClient)

	members, err := client.ListGroupMembers(context.Background(), &azureclient.Group{
		ID:           "group-id",
		MailNickname: "mail",
	})

	assert.EqualError(t, err, `list group members "mail": 404 Not Found: {"error":{"message":"some error"}}`)
	assert.Len(t, members, 0)
}

func Test_ListGroupMembersWithInvalidResponse(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			assert.Equal(t, "https://graph.microsoft.com/v1.0/groups/group-id/members", req.URL.String())
			assert.Equal(t, http.MethodGet, req.Method)

			return test.Response("200 OK", "some response")
		},
	)

	client := azureclient.New(httpClient)

	members, err := client.ListGroupMembers(context.Background(), &azureclient.Group{
		ID: "group-id",
	})

	assert.EqualError(t, err, "invalid character 's' looking for beginning of value")
	assert.Nil(t, members)
}

func Test_AddMemberToGroup(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			assert.Equal(t, "https://graph.microsoft.com/v1.0/groups/group-id/members/$ref", req.URL.String())
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, "application/json", req.Header.Get("content-type"))
			body, _ := io.ReadAll(req.Body)
			assert.Equal(t, `{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/user-id"}`, string(body))

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

	assert.NoError(t, err)
}

func Test_AddMemberToGroupWithInvalidResponse(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			assert.Equal(t, "https://graph.microsoft.com/v1.0/groups/group-id/members/$ref", req.URL.String())
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, "application/json", req.Header.Get("content-type"))

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

	assert.EqualError(t, err, `add member "mail@example.com" to azure group "group": 200 OK: some response body`)
}

func Test_RemoveMemberFromGroup(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			assert.Equal(t, "https://graph.microsoft.com/v1.0/groups/group-id/members/user-id/$ref", req.URL.String())
			assert.Equal(t, http.MethodDelete, req.Method)

			return test.Response("204 No Content", "")
		},
	)

	client := azureclient.New(httpClient)

	err := client.RemoveMemberFromGroup(context.Background(), &azureclient.Group{
		ID: "group-id",
	}, &azureclient.Member{
		ID: "user-id",
	})

	assert.NoError(t, err)
}

func Test_RemoveMemberFromGroupWithInvalidResponse(t *testing.T) {
	httpClient := test.NewTestHttpClient(
		func(req *http.Request) *http.Response {
			assert.Equal(t, "https://graph.microsoft.com/v1.0/groups/group-id/members/user-id/$ref", req.URL.String())
			assert.Equal(t, http.MethodDelete, req.Method)

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

	assert.EqualError(t, err, `remove member "mail" from azure group "mail@example.com": 200 OK: some response body`)
}

func Test_DeleteGroup(t *testing.T) {
	ctx := context.Background()
	grpID := uuid.New()

	t.Run("Successful delete", func(t *testing.T) {
		httpClient := test.NewTestHttpClient(
			func(req *http.Request) *http.Response {
				assert.Equal(t, fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s", grpID), req.URL.String())
				assert.Equal(t, http.MethodDelete, req.Method)
				assert.Equal(t, ctx, req.Context())
				return test.Response("204 No Content", "some response body")
			},
		)

		client := azureclient.New(httpClient)
		assert.NoError(t, client.DeleteGroup(ctx, grpID))
	})

	t.Run("Delete error", func(t *testing.T) {
		httpClient := test.NewTestHttpClient(
			func(req *http.Request) *http.Response {
				return test.Response("200 OK", "some response body")
			},
		)

		client := azureclient.New(httpClient)
		err := client.DeleteGroup(ctx, grpID)
		assert.ErrorContains(t, err, "remove azure group with ID")
		assert.ErrorContains(t, err, grpID.String())
	})
}
