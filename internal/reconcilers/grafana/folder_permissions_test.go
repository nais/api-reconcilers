package grafana_reconciler

import (
	"context"
	"errors"
	"strings"
	"testing"

	grafanafolderpermissions "github.com/grafana/grafana-openapi-client-go/client/folder_permissions"
	"github.com/grafana/grafana-openapi-client-go/models"
)

func TestSetFolderTeamPermissions(t *testing.T) {
	ctx := context.Background()
	const folderUID = "team-folder-uid"
	const teamID int64 = 10

	tests := []struct {
		name     string
		existing []*models.DashboardACLInfoDTO
		want     []*models.DashboardACLUpdateItem
	}{
		{
			name: "grants team edit and everyone else view",
			existing: []*models.DashboardACLInfoDTO{
				{Role: "Viewer", Permission: 1},
				{Role: "Editor", Permission: 2},
				{UserID: 20, Permission: 4},
				{TeamID: 30, Permission: 2},
				{TeamID: 40, Permission: 1, Inherited: true},
			},
			want: []*models.DashboardACLUpdateItem{
				{Role: "Viewer", Permission: 1},
				{Role: "Editor", Permission: 1},
				{UserID: 20, Permission: 1},
				{TeamID: 30, Permission: 1},
				{TeamID: teamID, Permission: 2},
			},
		},
		{
			name:     "upgrades existing team view access",
			existing: []*models.DashboardACLInfoDTO{{TeamID: teamID, Permission: 1}},
			want: []*models.DashboardACLUpdateItem{
				{TeamID: teamID, Permission: 2},
				{Role: "Viewer", Permission: 1},
				{Role: "Editor", Permission: 1},
			},
		},
		{
			name:     "adds direct access if only inherited access exists",
			existing: []*models.DashboardACLInfoDTO{{TeamID: teamID, Permission: 1, Inherited: true}},
			want: []*models.DashboardACLUpdateItem{
				{Role: "Viewer", Permission: 1},
				{Role: "Editor", Permission: 1},
				{TeamID: teamID, Permission: 2},
			},
		},
		{
			name: "leaves matching permissions unchanged",
			existing: []*models.DashboardACLInfoDTO{
				{Role: "Viewer", Permission: 1},
				{Role: "Editor", Permission: 1},
				{TeamID: teamID, Permission: 2},
			},
		},
		{
			name: "does not downgrade owning team admin permission",
			existing: []*models.DashboardACLInfoDTO{
				{Role: "Viewer", Permission: 1},
				{Role: "Editor", Permission: 1},
				{TeamID: teamID, Permission: 4},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permissions := NewMockFolderPermissionsClientService(t)
			permissions.EXPECT().
				GetFolderPermissionListWithParams(&grafanafolderpermissions.GetFolderPermissionListParams{
					FolderUID: folderUID, Context: ctx,
				}).
				Return(&grafanafolderpermissions.GetFolderPermissionListOK{Payload: tt.existing}, nil).
				Once()
			if tt.want != nil {
				permissions.EXPECT().
					UpdateFolderPermissionsWithParams(&grafanafolderpermissions.UpdateFolderPermissionsParams{
						FolderUID: folderUID,
						Body:      &models.UpdateDashboardACLCommand{Items: tt.want},
						Context:   ctx,
					}).
					Return(&grafanafolderpermissions.UpdateFolderPermissionsOK{}, nil).
					Once()
			}

			if err := (&grafanaReconciler{folderPermissions: permissions}).setFolderTeamPermissions(ctx, folderUID, teamID); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("returns read errors", func(t *testing.T) {
		permissions := NewMockFolderPermissionsClientService(t)
		permissions.EXPECT().
			GetFolderPermissionListWithParams(&grafanafolderpermissions.GetFolderPermissionListParams{
				FolderUID: folderUID, Context: ctx,
			}).
			Return(nil, errors.New("read failed")).
			Once()

		err := (&grafanaReconciler{folderPermissions: permissions}).setFolderTeamPermissions(ctx, folderUID, teamID)
		if err == nil || !strings.Contains(err.Error(), "read failed") {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("rejects inherited access that cannot be reduced", func(t *testing.T) {
		permissions := NewMockFolderPermissionsClientService(t)
		permissions.EXPECT().
			GetFolderPermissionListWithParams(&grafanafolderpermissions.GetFolderPermissionListParams{
				FolderUID: folderUID, Context: ctx,
			}).
			Return(&grafanafolderpermissions.GetFolderPermissionListOK{Payload: []*models.DashboardACLInfoDTO{
				{Role: "Editor", Permission: 2, Inherited: true},
			}}, nil).
			Once()

		err := (&grafanaReconciler{folderPermissions: permissions}).setFolderTeamPermissions(ctx, folderUID, teamID)
		if err == nil || !strings.Contains(err.Error(), "inherited Edit") {
			t.Fatalf("expected inherited permission error, got %v", err)
		}
	})

	t.Run("returns update errors", func(t *testing.T) {
		permissions := NewMockFolderPermissionsClientService(t)
		permissions.EXPECT().
			GetFolderPermissionListWithParams(&grafanafolderpermissions.GetFolderPermissionListParams{
				FolderUID: folderUID, Context: ctx,
			}).
			Return(&grafanafolderpermissions.GetFolderPermissionListOK{}, nil).
			Once()
		permissions.EXPECT().
			UpdateFolderPermissionsWithParams(&grafanafolderpermissions.UpdateFolderPermissionsParams{
				FolderUID: folderUID,
				Body: &models.UpdateDashboardACLCommand{Items: []*models.DashboardACLUpdateItem{
					{Role: "Viewer", Permission: 1},
					{Role: "Editor", Permission: 1},
					{TeamID: teamID, Permission: 2},
				}},
				Context: ctx,
			}).
			Return(nil, errors.New("update failed")).
			Once()

		err := (&grafanaReconciler{folderPermissions: permissions}).setFolderTeamPermissions(ctx, folderUID, teamID)
		if err == nil || !strings.Contains(err.Error(), "update failed") {
			t.Fatalf("expected update error, got %v", err)
		}
	})
}
