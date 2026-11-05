package azure_group_reconciler

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/nais/api-reconcilers/internal/azureclient"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestConnectParentGroup(t *testing.T) {
	for _, name := range []string{"existing parent", "create parent", "already linked", "lookup failure", "creation failure", "list failure", "add failure", "retry after add failure", "self membership", "invalid parent"} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			client := azureclient.NewMockClient(t)
			r := &azureGroupReconciler{}
			parent := &azureclient.Group{ID: "parent-id", MailNickname: parentGroupName, SecurityEnabled: true}
			child := &azureclient.Group{ID: "child-id", MailNickname: "nais-team-test"}
			failure := errors.New("graph failed")
			var expectedErr string
			switch name {
			case "lookup failure":
				client.EXPECT().GetGroupByMailNickname(ctx, parentGroupName).Return(nil, failure).Once()
				expectedErr = "get Azure parent group"
			case "create parent", "creation failure":
				client.EXPECT().GetGroupByMailNickname(ctx, parentGroupName).Return(nil, nil).Once()
				create := client.EXPECT().CreateGroup(ctx, &azureclient.Group{
					Description: "Parent group for all teams synced by Nais.", DisplayName: parentGroupName,
					MailNickname: parentGroupName, SecurityEnabled: true,
				}).Once()
				if name == "creation failure" {
					create.Return(nil, failure)
					expectedErr = "create Azure parent group"
				} else {
					create.Return(parent, nil)
				}
			default:
				client.EXPECT().GetGroupByMailNickname(ctx, parentGroupName).Return(parent, nil).Once()
			}
			if name == "self membership" {
				child.ID = parent.ID
				expectedErr = "reserved for the parent group"
			}
			if name == "invalid parent" {
				parent.GroupTypes = []string{"DynamicMembership"}
				expectedErr = "must be an assigned, mail-disabled security group"
			}
			membershipParent := &azureclient.Group{ID: parent.ID, MailNickname: parentGroupName}
			if expectedErr == "" {
				switch name {
				case "already linked":
					client.EXPECT().ListGroupMembers(ctx, membershipParent).Return([]*azureclient.Member{{ID: child.ID}}, nil).Once()
				case "list failure":
					client.EXPECT().ListGroupMembers(ctx, membershipParent).Return(nil, failure).Once()
					expectedErr = "list members of Azure parent group"
				default:
					// An unrelated member must never be removed from the shared parent.
					client.EXPECT().ListGroupMembers(ctx, membershipParent).Return([]*azureclient.Member{{ID: "unrelated"}}, nil).Once()
					add := client.EXPECT().AddMemberToGroup(ctx, membershipParent, &azureclient.Member{ID: child.ID}).Once()
					if name == "add failure" || name == "retry after add failure" {
						add.Return(failure)
						expectedErr = "add Azure group"
					} else {
						add.Return(nil)
					}
				}
			}
			parentID, err := r.getOrCreateParentGroup(ctx, client)
			if err == nil {
				err = r.connectParentGroup(ctx, client, parentID, child)
			}
			if expectedErr != "" {
				require.ErrorContains(t, err, expectedErr)
			} else {
				require.NoError(t, err)
			}
			if name == "retry after add failure" {
				// The previous request may have succeeded remotely despite returning an error.
				client.EXPECT().GetGroupByMailNickname(ctx, parentGroupName).Return(parent, nil).Once()
				client.EXPECT().ListGroupMembers(ctx, membershipParent).Return([]*azureclient.Member{{ID: child.ID}}, nil).Once()
				parentID, err := r.getOrCreateParentGroup(ctx, client)
				require.NoError(t, err)
				require.NoError(t, r.connectParentGroup(ctx, client, parentID, child))
			}
		})
	}
}

func TestParentGroupNameIsReserved(t *testing.T) {
	ctx := t.Context()
	client := azureclient.NewMockClient(t)
	api, _ := apiclient.NewMockClient(t)
	log, _ := test.NewNullLogger()
	r := New(ctx, "example.com", "nais-", WithAzureClient(client))
	require.ErrorContains(t, r.Reconcile(ctx, api, &protoapi.Team{Slug: "teams"}, log), "reserved for the parent group")
}

func TestParentGroupFailureStopsReconciliation(t *testing.T) {
	ctx := t.Context()
	client := azureclient.NewMockClient(t)
	api, _ := apiclient.NewMockClient(t)
	log, _ := test.NewNullLogger()
	team := &protoapi.Team{Slug: "test", EntraIdGroupId: new("child-id")}
	client.EXPECT().GetGroupByMailNickname(ctx, parentGroupName).Return(nil, errors.New("graph failed")).Once()
	r := New(ctx, "example.com", "nais-team-", WithAzureClient(client))
	require.ErrorContains(t, r.Reconcile(ctx, api, team, log), "get Azure parent group")
	// Neither team group creation, user synchronization nor membership mutations are expected.
}

func TestParentGroupIsRecreated(t *testing.T) {
	ctx := t.Context()
	client := azureclient.NewMockClient(t)
	r := &azureGroupReconciler{}
	child := &azureclient.Group{ID: "child-id"}
	parent := &azureclient.Group{ID: "old-parent-id", SecurityEnabled: true}
	client.EXPECT().GetGroupByMailNickname(ctx, parentGroupName).Return(parent, nil).Once()
	client.EXPECT().ListGroupMembers(ctx, &azureclient.Group{ID: parent.ID, MailNickname: parentGroupName}).Return([]*azureclient.Member{{ID: child.ID}}, nil).Once()
	parentID, err := r.getOrCreateParentGroup(ctx, client)
	require.NoError(t, err)
	require.Equal(t, parent.ID, parentID)
	require.NoError(t, r.connectParentGroup(ctx, client, parentID, child))

	replacement := &azureclient.Group{ID: "new-parent-id", SecurityEnabled: true}
	client.EXPECT().GetGroupByMailNickname(ctx, parentGroupName).Return(nil, nil).Once()
	client.EXPECT().CreateGroup(ctx, mock.Anything).Return(replacement, nil).Once()
	membershipParent := &azureclient.Group{ID: replacement.ID, MailNickname: parentGroupName}
	client.EXPECT().ListGroupMembers(ctx, membershipParent).Return(nil, nil).Once()
	client.EXPECT().AddMemberToGroup(ctx, membershipParent, &azureclient.Member{ID: child.ID}).Return(nil).Once()
	parentID, err = r.getOrCreateParentGroup(ctx, client)
	require.NoError(t, err)
	require.Equal(t, replacement.ID, parentID)
	require.NoError(t, r.connectParentGroup(ctx, client, parentID, child))
}

func TestConcurrentParentGroupCreation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		client := azureclient.NewMockClient(t)
		r := &azureGroupReconciler{}
		const workers = 10
		var parent *azureclient.Group
		// These callbacks are serialized by the reconciler's parent lock.
		client.EXPECT().GetGroupByMailNickname(ctx, parentGroupName).
			RunAndReturn(func(context.Context, string) (*azureclient.Group, error) { return parent, nil }).Times(workers)
		client.EXPECT().CreateGroup(ctx, mock.Anything).
			RunAndReturn(func(context.Context, *azureclient.Group) (*azureclient.Group, error) {
				parent = &azureclient.Group{ID: "parent-id", SecurityEnabled: true}
				return parent, nil
			}).Once()
		var membershipUpdates atomic.Int32
		release := make(chan struct{})
		client.EXPECT().ListGroupMembers(ctx, mock.Anything).
			RunAndReturn(func(context.Context, *azureclient.Group) ([]*azureclient.Member, error) {
				membershipUpdates.Add(1)
				<-release
				return nil, nil
			}).Times(workers)
		client.EXPECT().AddMemberToGroup(ctx, mock.Anything, mock.Anything).Return(nil).Times(workers)
		errors := make(chan error, workers)
		for i := range workers {
			go func() {
				parentID, err := r.getOrCreateParentGroup(ctx, client)
				if err == nil {
					err = r.connectParentGroup(ctx, client, parentID, &azureclient.Group{ID: fmt.Sprintf("child-%d", i)})
				}
				errors <- err
			}()
		}
		synctest.Wait()
		// Every worker can reach membership synchronization while the others are blocked there.
		assert.Equal(t, int32(workers), membershipUpdates.Load())
		close(release)
		for range workers {
			require.NoError(t, <-errors)
		}
	})
}
