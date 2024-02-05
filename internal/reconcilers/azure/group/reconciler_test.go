package azure_group_reconciler_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nais/api-reconcilers/internal/azureclient"
	azure_group_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/azure/group"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/status"
)

func TestAzureReconciler_Reconcile(t *testing.T) {
	domain := "example.com"
	teamSlug := "slug"
	teamPurpose := "My purpose"
	log, _ := test.NewNullLogger()

	ctx := context.Background()

	group := &azureclient.Group{
		ID:           "some-group-id",
		MailNickname: "nais-team-myteam",
	}
	addMember := &azureclient.Member{
		ID:   "some-addMember-id",
		Mail: "add@example.com",
	}
	keepMember := &azureclient.Member{
		ID:   "some-keepmember-id",
		Mail: "keeper@example.com",
	}
	removeMember := &azureclient.Member{
		ID:   "some-removeMember-id",
		Mail: "removemember@example.com",
	}
	addUser := &protoapi.User{
		Email: "add@example.com",
	}
	keepUser := &protoapi.User{
		Email: "keeper@example.com",
	}
	team := &protoapi.Team{
		Slug:    teamSlug,
		Purpose: teamPurpose,
	}

	t.Run("happy case", func(t *testing.T) {
		mockClient := azureclient.NewMockClient(t)
		mockClient.EXPECT().
			GetOrCreateGroup(mock.Anything, mock.Anything, "nais-team-slug").
			Return(group, true, nil).
			Once()
		mockClient.EXPECT().
			ListGroupMembers(mock.Anything, group).
			Return([]*azureclient.Member{keepMember, removeMember}, nil).
			Once()
		mockClient.EXPECT().
			RemoveMemberFromGroup(mock.Anything, group, removeMember).
			Return(nil).
			Once()
		mockClient.EXPECT().
			GetUser(mock.Anything, addUser.Email).
			Return(addMember, nil).
			Once()
		mockClient.EXPECT().
			AddMemberToGroup(mock.Anything, group, addMember).
			Return(nil).
			Once()

		client, mockServer := apiclient.NewMockClient(t)
		mockServer.Reconcilers.EXPECT().
			Config(mock.Anything, &protoapi.ConfigReconcilerRequest{ReconcilerName: "azure:group"}).
			Return(&protoapi.ConfigReconcilerResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			SetTeamExternalReferences(mock.Anything, &protoapi.SetTeamExternalReferencesRequest{
				Slug:         teamSlug,
				AzureGroupId: &group.ID,
			}).
			Return(&protoapi.SetTeamExternalReferencesResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Limit: 100, Offset: 0, Slug: teamSlug}).
			Return(&protoapi.ListTeamMembersResponse{Nodes: []*protoapi.TeamMember{
				{User: addUser}, {User: keepUser},
			}}, nil).
			Once()
		mockServer.Users.EXPECT().
			Get(mock.Anything, mock.AnythingOfType("*protoapi.GetUserRequest")).
			RunAndReturn(func(ctx context.Context, gur *protoapi.GetUserRequest) (*protoapi.GetUserResponse, error) {
				switch gur.Email {
				case addUser.Email:
					return &protoapi.GetUserResponse{User: addUser}, nil
				case keepUser.Email:
					return &protoapi.GetUserResponse{User: keepUser}, nil
				}
				return nil, status.Error(404, "not found")
			}).
			Times(3)
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "azure:group:create"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "azure:group:add-member"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		err := azure_group_reconciler.
			New(domain, azure_group_reconciler.WithAzureClient(mockClient)).
			Reconcile(ctx, client, team, log)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("GetOrCreateGroup fail", func(t *testing.T) {
		client, _ := apiclient.NewMockClient(t)
		mockClient := azureclient.NewMockClient(t)

		mockClient.EXPECT().
			GetOrCreateGroup(mock.Anything, mock.Anything, "nais-team-slug").
			Return(nil, false, fmt.Errorf("GetOrCreateGroup failed")).
			Once()

		err := azure_group_reconciler.
			New(domain, azure_group_reconciler.WithAzureClient(mockClient)).
			Reconcile(ctx, client, team, log)

		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("ListGroupMembers fail", func(t *testing.T) {
		client, mockServer := apiclient.NewMockClient(t)
		mockClient := azureclient.NewMockClient(t)

		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Limit: 100, Offset: 0, Slug: teamSlug}).
			Return(&protoapi.ListTeamMembersResponse{Nodes: []*protoapi.TeamMember{
				{User: addUser}, {User: keepUser},
			}}, nil).
			Once()

		mockClient.EXPECT().
			GetOrCreateGroup(mock.Anything, mock.Anything, "nais-team-slug").
			Return(group, false, nil).
			Once()
		mockClient.EXPECT().
			ListGroupMembers(mock.Anything, group).
			Return(nil, fmt.Errorf("ListGroupMembers failed")).
			Once()

		err := azure_group_reconciler.
			New(domain, azure_group_reconciler.WithAzureClient(mockClient)).
			Reconcile(ctx, client, team, log)

		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("RemoveMemberFromGroup fail", func(t *testing.T) {
		client, mockServer := apiclient.NewMockClient(t)
		mockClient := azureclient.NewMockClient(t)
		removeMemberFromGroupErr := errors.New("RemoveMemberFromGroup failed")

		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Limit: 100, Offset: 0, Slug: teamSlug}).
			Return(&protoapi.ListTeamMembersResponse{Nodes: []*protoapi.TeamMember{
				{User: keepUser},
			}}, nil).
			Once()

		mockClient.EXPECT().
			GetOrCreateGroup(mock.Anything, mock.Anything, "nais-team-slug").
			Return(group, false, nil).
			Once()
		mockClient.EXPECT().
			ListGroupMembers(mock.Anything, group).
			Return([]*azureclient.Member{keepMember, removeMember}, nil).
			Once()
		mockClient.EXPECT().
			RemoveMemberFromGroup(mock.Anything, group, removeMember).
			Return(removeMemberFromGroupErr).
			Once()

		err := azure_group_reconciler.
			New(domain, azure_group_reconciler.WithAzureClient(mockClient)).
			Reconcile(ctx, client, team, log)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("GetUser fail", func(t *testing.T) {
		client, mockServer := apiclient.NewMockClient(t)
		mockClient := azureclient.NewMockClient(t)
		getUserError := errors.New("GetUser failed")

		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Limit: 100, Offset: 0, Slug: teamSlug}).
			Return(&protoapi.ListTeamMembersResponse{Nodes: []*protoapi.TeamMember{
				{User: addUser}, {User: keepUser},
			}}, nil).
			Once()
		mockServer.Users.EXPECT().
			Get(mock.Anything, mock.AnythingOfType("*protoapi.GetUserRequest")).
			RunAndReturn(func(ctx context.Context, gur *protoapi.GetUserRequest) (*protoapi.GetUserResponse, error) {
				switch gur.Email {
				case addUser.Email:
					return &protoapi.GetUserResponse{User: addUser}, nil
				case keepUser.Email:
					return &protoapi.GetUserResponse{User: keepUser}, nil
				}
				return nil, status.Error(404, "not found")
			}).
			Times(2)

		mockClient.EXPECT().
			GetOrCreateGroup(mock.Anything, mock.Anything, "nais-team-slug").
			Return(group, false, nil).
			Once()
		mockClient.EXPECT().
			ListGroupMembers(mock.Anything, group).
			Return([]*azureclient.Member{keepMember, removeMember}, nil).
			Once()
		mockClient.EXPECT().
			RemoveMemberFromGroup(mock.Anything, group, removeMember).
			Return(nil).
			Once()
		mockClient.EXPECT().
			GetUser(mock.Anything, addUser.Email).
			Return(nil, getUserError).
			Once()

		err := azure_group_reconciler.
			New(domain, azure_group_reconciler.WithAzureClient(mockClient)).
			Reconcile(ctx, client, team, log)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("AddMemberToGroup fail", func(t *testing.T) {
		client, mockServer := apiclient.NewMockClient(t)
		mockClient := azureclient.NewMockClient(t)
		addMemberToGroupError := errors.New("AddMemberToGroup failed")

		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Limit: 100, Offset: 0, Slug: teamSlug}).
			Return(&protoapi.ListTeamMembersResponse{Nodes: []*protoapi.TeamMember{
				{User: addUser}, {User: keepUser},
			}}, nil).
			Once()

		mockClient.EXPECT().
			GetOrCreateGroup(mock.Anything, mock.Anything, "nais-team-slug").
			Return(group, false, nil).
			Once()
		mockClient.EXPECT().
			ListGroupMembers(mock.Anything, group).
			Return([]*azureclient.Member{keepMember}, nil).
			Once()
		mockClient.EXPECT().
			GetUser(mock.Anything, addUser.Email).
			Return(addMember, nil).
			Once()
		mockClient.EXPECT().
			AddMemberToGroup(mock.Anything, group, addMember).
			Return(addMemberToGroupError).
			Once()

		err := azure_group_reconciler.
			New(domain, azure_group_reconciler.WithAzureClient(mockClient)).
			Reconcile(ctx, client, team, log)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})
}

func TestAzureReconciler_Delete(t *testing.T) {
	const domain = "example.com"

	azGroupID := uuid.New()
	team := &protoapi.Team{
		Slug:         "slug",
		AzureGroupId: azGroupID.String(),
	}
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	azureClient := azureclient.NewMockClient(t)

	t.Run("Empty group id", func(t *testing.T) {
		client, _ := apiclient.NewMockClient(t)

		err := azure_group_reconciler.
			New(domain, azure_group_reconciler.WithAzureClient(azureClient)).
			Delete(ctx, client, &protoapi.Team{Slug: "some-slug"}, log)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("Azure client error", func(t *testing.T) {
		client, _ := apiclient.NewMockClient(t)

		azureClient := azureclient.NewMockClient(t)
		azureClient.EXPECT().
			DeleteGroup(ctx, azGroupID).
			Return(fmt.Errorf("some error")).
			Once()

		err := azure_group_reconciler.
			New(domain, azure_group_reconciler.WithAzureClient(azureClient)).
			Delete(ctx, client, team, log)

		if !strings.Contains(err.Error(), "delete Azure AD group with ID") {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("Successful delete", func(t *testing.T) {
		client, mockServer := apiclient.NewMockClient(t)
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(r *protoapi.CreateAuditLogsRequest) bool {
				return r.Action == "azure:group:delete"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		azureClient := azureclient.NewMockClient(t)
		azureClient.EXPECT().
			DeleteGroup(ctx, azGroupID).
			Return(nil).
			Once()

		err := azure_group_reconciler.
			New(domain, azure_group_reconciler.WithAzureClient(azureClient)).
			Delete(ctx, client, team, log)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})
}
