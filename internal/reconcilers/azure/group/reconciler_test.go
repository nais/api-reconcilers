package azure_group_reconciler_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/nais/api-reconcilers/internal/azureclient"
	azure_group_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/azure/group"
	"github.com/nais/api/pkg/apiclient"
	db "github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
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
	addUser := &db.User{
		Email: "add@example.com",
	}
	keepUser := &db.User{
		Email: "keeper@example.com",
	}
	team := &db.Team{
		Slug:    teamSlug,
		Purpose: teamPurpose,
	}

	t.Run("happy case", func(t *testing.T) {
		client, mockServer := apiclient.NewMockClient(t)
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

		mockServer.Reconcilers.EXPECT().
			Config(mock.Anything, &db.ConfigReconcilerRequest{ReconcilerName: "azure:group"}).
			Return(&db.ConfigReconcilerResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			SetTeamExternalReferences(mock.Anything, &db.SetTeamExternalReferencesRequest{
				Slug:         teamSlug,
				AzureGroupId: &group.ID,
			}).
			Return(&db.SetTeamExternalReferencesResponse{}, nil).
			Once()
		mockServer.Teams.EXPECT().
			Members(mock.Anything, &db.ListTeamMembersRequest{Slug: teamSlug}).
			Return(&db.ListTeamMembersResponse{Nodes: []*db.TeamMember{
				{User: addUser}, {User: keepUser},
			}}, nil).
			Once()
		mockServer.Users.EXPECT().
			Get(mock.Anything, mock.AnythingOfType("*protoapi.GetUserRequest")).
			RunAndReturn(func(ctx context.Context, gur *db.GetUserRequest) (*db.GetUserResponse, error) {
				switch gur.Email {
				case addUser.Email:
					return &db.GetUserResponse{User: addUser}, nil
				case keepUser.Email:
					return &db.GetUserResponse{User: keepUser}, nil
				}
				return nil, status.Error(404, "not found")
			}).
			Times(3)

		err := azure_group_reconciler.
			New(ctx, domain, client, azure_group_reconciler.WithAzureClient(mockClient)).
			Reconcile(ctx, client, team, log)

		assert.NoError(t, err)
	})

	t.Run("GetOrCreateGroup fail", func(t *testing.T) {
		client, _ := apiclient.NewMockClient(t)
		mockClient := azureclient.NewMockClient(t)

		mockClient.EXPECT().
			GetOrCreateGroup(mock.Anything, mock.Anything, "nais-team-slug").
			Return(nil, false, fmt.Errorf("GetOrCreateGroup failed")).
			Once()

		err := azure_group_reconciler.
			New(ctx, domain, client, azure_group_reconciler.WithAzureClient(mockClient)).
			Reconcile(ctx, client, team, log)
		assert.Error(t, err)
	})

	t.Run("ListGroupMembers fail", func(t *testing.T) {
		client, mockServer := apiclient.NewMockClient(t)
		mockClient := azureclient.NewMockClient(t)

		mockServer.Teams.EXPECT().
			Members(mock.Anything, &db.ListTeamMembersRequest{Slug: teamSlug}).
			Return(&db.ListTeamMembersResponse{Nodes: []*db.TeamMember{
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
			New(ctx, domain, client, azure_group_reconciler.WithAzureClient(mockClient)).
			Reconcile(ctx, client, team, log)
		assert.Error(t, err)
	})

	t.Run("RemoveMemberFromGroup fail", func(t *testing.T) {
		client, mockServer := apiclient.NewMockClient(t)
		mockClient := azureclient.NewMockClient(t)
		removeMemberFromGroupErr := errors.New("RemoveMemberFromGroup failed")

		mockServer.Teams.EXPECT().
			Members(mock.Anything, &db.ListTeamMembersRequest{Slug: teamSlug}).
			Return(&db.ListTeamMembersResponse{Nodes: []*db.TeamMember{
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
			New(ctx, domain, client, azure_group_reconciler.WithAzureClient(mockClient)).
			Reconcile(ctx, client, team, log)
		assert.NoError(t, err)
	})

	t.Run("GetUser fail", func(t *testing.T) {
		client, mockServer := apiclient.NewMockClient(t)
		mockClient := azureclient.NewMockClient(t)
		getUserError := errors.New("GetUser failed")

		mockServer.Teams.EXPECT().
			Members(mock.Anything, &db.ListTeamMembersRequest{Slug: teamSlug}).
			Return(&db.ListTeamMembersResponse{Nodes: []*db.TeamMember{
				{User: addUser}, {User: keepUser},
			}}, nil).
			Once()
		mockServer.Users.EXPECT().
			Get(mock.Anything, mock.AnythingOfType("*protoapi.GetUserRequest")).
			RunAndReturn(func(ctx context.Context, gur *db.GetUserRequest) (*db.GetUserResponse, error) {
				switch gur.Email {
				case addUser.Email:
					return &db.GetUserResponse{User: addUser}, nil
				case keepUser.Email:
					return &db.GetUserResponse{User: keepUser}, nil
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
			New(ctx, domain, client, azure_group_reconciler.WithAzureClient(mockClient)).
			Reconcile(ctx, client, team, log)
		assert.NoError(t, err)
	})

	t.Run("AddMemberToGroup fail", func(t *testing.T) {
		client, mockServer := apiclient.NewMockClient(t)
		mockClient := azureclient.NewMockClient(t)
		addMemberToGroupError := errors.New("AddMemberToGroup failed")

		mockServer.Teams.EXPECT().
			Members(mock.Anything, &db.ListTeamMembersRequest{Slug: teamSlug}).
			Return(&db.ListTeamMembersResponse{Nodes: []*db.TeamMember{
				{User: addUser}, {User: keepUser},
			}}, nil).
			Once()

		mockClient.
			On("GetOrCreateGroup", mock.Anything, mock.Anything, "nais-team-slug", mock.Anything).
			Return(group, false, nil).
			Once()
		mockClient.
			On("ListGroupMembers", mock.Anything, group).
			Return([]*azureclient.Member{keepMember}, nil).
			Once()
		mockClient.
			On("GetUser", mock.Anything, addUser.Email).
			Return(addMember, nil).
			Once()
		mockClient.
			On("AddMemberToGroup", mock.Anything, group, addMember).
			Return(addMemberToGroupError).
			Once()

		err := azure_group_reconciler.
			New(ctx, domain, client, azure_group_reconciler.WithAzureClient(mockClient)).
			Reconcile(ctx, client, team, log)
		assert.NoError(t, err)
	})
}

func TestAzureReconciler_Delete(t *testing.T) {
	const domain = "example.com"

	azGroupID := uuid.New()
	team := &db.Team{
		Slug:         "slug",
		AzureGroupId: azGroupID.String(),
	}
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	azureClient := azureclient.NewMockClient(t)

	// t.Run("Unable to load state", func(t *testing.T) {
	// 	client, _ := apiclient.NewMockClient(t)
	// 	// database.
	// 	// 	On("LoadReconcilerStateForTeam", ctx, azure_group_reconciler.Name, teamSlug, mock.Anything).
	// 	// 	Return(fmt.Errorf("some error")).
	// 	// 	Once()

	// 	err := azure_group_reconciler.
	// 		New(ctx, domain, client, azure_group_reconciler.WithAzureClient(azureClient)).
	// 		Delete(ctx, client, team, log)
	// 	assert.ErrorContains(t, err, "load reconciler state")
	// })

	t.Run("Empty group id", func(t *testing.T) {
		client, _ := apiclient.NewMockClient(t)

		err := azure_group_reconciler.
			New(ctx, domain, client, azure_group_reconciler.WithAzureClient(azureClient)).
			Delete(ctx, client, &db.Team{Slug: "some-slug"}, log)
		assert.NoError(t, err)
	})

	t.Run("Azure client error", func(t *testing.T) {
		client, _ := apiclient.NewMockClient(t)

		azureClient := azureclient.NewMockClient(t)
		azureClient.
			On("DeleteGroup", ctx, azGroupID).
			Return(fmt.Errorf("some error")).
			Once()

		err := azure_group_reconciler.
			New(ctx, domain, client, azure_group_reconciler.WithAzureClient(azureClient)).
			Delete(ctx, client, team, log)
		assert.ErrorContains(t, err, "delete Azure AD group with ID")
	})

	t.Run("Successful delete", func(t *testing.T) {
		client, _ := apiclient.NewMockClient(t)

		azureClient := azureclient.NewMockClient(t)
		azureClient.
			On("DeleteGroup", ctx, azGroupID).
			Return(nil).
			Once()

		err := azure_group_reconciler.
			New(ctx, domain, client, azure_group_reconciler.WithAzureClient(azureClient)).
			Delete(ctx, client, team, log)
		assert.Nil(t, err)
	})
}
