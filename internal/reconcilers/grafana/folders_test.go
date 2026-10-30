package grafana_reconciler

import (
	"context"
	"errors"
	"strings"
	"testing"

	grafanafolders "github.com/grafana/grafana-openapi-client-go/client/folders"
	"github.com/grafana/grafana-openapi-client-go/models"
)

func TestGetOrCreateFolder(t *testing.T) {
	ctx := context.Background()
	teamName := "my-team"
	limit, firstPage, secondPage := int64(1000), int64(1), int64(2)
	listParams := func(page *int64) *grafanafolders.GetFoldersParams {
		return &grafanafolders.GetFoldersParams{Limit: &limit, Page: page, Context: ctx}
	}

	t.Run("finds existing folder on a later page", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		hits := make([]*models.FolderSearchHit, limit)
		for i := range hits {
			hits[i] = &models.FolderSearchHit{Title: "another-team"}
		}
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: hits}, nil).Once()
		folders.EXPECT().GetFolders(listParams(&secondPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: []*models.FolderSearchHit{{Title: teamName, UID: "existing-uid"}}}, nil).Once()
		folders.EXPECT().GetFolderByUIDWithParams(&grafanafolders.GetFolderByUIDParams{
			FolderUID: "existing-uid", Context: ctx,
		}).Return(&grafanafolders.GetFolderByUIDOK{Payload: &models.Folder{Version: 2}}, nil).Once()
		folders.EXPECT().UpdateFolderWithParams(&grafanafolders.UpdateFolderParams{
			FolderUID: "existing-uid",
			Body: &models.UpdateFolderCommand{
				Description: "Reconciled by nais",
				Version:     2,
			},
			Context: ctx,
		}).Return(&grafanafolders.UpdateFolderOK{}, nil).Once()

		uid, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err != nil || uid != "existing-uid" {
			t.Fatalf("expected existing-uid, got %q, %v", uid, err)
		}
	})

	t.Run("restores the title of a renamed stable UID folder", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: []*models.FolderSearchHit{
				{Title: "renamed", UID: "nais-" + teamName},
			}}, nil).Once()
		folders.EXPECT().GetFolderByUIDWithParams(&grafanafolders.GetFolderByUIDParams{
			FolderUID: "nais-" + teamName, Context: ctx,
		}).Return(&grafanafolders.GetFolderByUIDOK{Payload: &models.Folder{Version: 2}}, nil).Once()
		folders.EXPECT().UpdateFolderWithParams(&grafanafolders.UpdateFolderParams{
			FolderUID: "nais-" + teamName,
			Body: &models.UpdateFolderCommand{
				Title:       teamName,
				Description: "Reconciled by nais",
				Version:     2,
			},
			Context: ctx,
		}).Return(&grafanafolders.UpdateFolderOK{}, nil).Once()

		uid, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err != nil || uid != "nais-"+teamName {
			t.Fatalf("expected stable UID, got %q, %v", uid, err)
		}
	})

	t.Run("prefers stable UID over duplicate titles", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: []*models.FolderSearchHit{
				{Title: teamName, UID: "legacy-uid"},
				{Title: teamName, UID: "nais-" + teamName},
			}}, nil).Once()
		folders.EXPECT().GetFolderByUIDWithParams(&grafanafolders.GetFolderByUIDParams{
			FolderUID: "nais-" + teamName, Context: ctx,
		}).Return(&grafanafolders.GetFolderByUIDOK{Payload: &models.Folder{Version: 2}}, nil).Once()
		folders.EXPECT().UpdateFolderWithParams(&grafanafolders.UpdateFolderParams{
			FolderUID: "nais-" + teamName,
			Body: &models.UpdateFolderCommand{
				Description: "Reconciled by nais",
				Version:     2,
			},
			Context: ctx,
		}).Return(&grafanafolders.UpdateFolderOK{}, nil).Once()

		uid, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err != nil || uid != "nais-"+teamName {
			t.Fatalf("expected stable UID, got %q, %v", uid, err)
		}
	})

	t.Run("finds stable UID after a legacy title match on a later page", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		hits := make([]*models.FolderSearchHit, limit)
		for i := range hits {
			hits[i] = &models.FolderSearchHit{Title: "another-team"}
		}
		hits[0] = &models.FolderSearchHit{Title: teamName, UID: "legacy-uid"}
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: hits}, nil).Once()
		folders.EXPECT().GetFolders(listParams(&secondPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: []*models.FolderSearchHit{
				{Title: teamName, UID: "nais-" + teamName},
			}}, nil).Once()
		folders.EXPECT().GetFolderByUIDWithParams(&grafanafolders.GetFolderByUIDParams{
			FolderUID: "nais-" + teamName, Context: ctx,
		}).Return(&grafanafolders.GetFolderByUIDOK{Payload: &models.Folder{Version: 2}}, nil).Once()
		folders.EXPECT().UpdateFolderWithParams(&grafanafolders.UpdateFolderParams{
			FolderUID: "nais-" + teamName,
			Body: &models.UpdateFolderCommand{
				Description: "Reconciled by nais",
				Version:     2,
			},
			Context: ctx,
		}).Return(&grafanafolders.UpdateFolderOK{}, nil).Once()

		uid, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err != nil || uid != "nais-"+teamName {
			t.Fatalf("expected stable UID, got %q, %v", uid, err)
		}
	})

	t.Run("rejects a title conflict when restoring a renamed stable folder", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: []*models.FolderSearchHit{
				{Title: "renamed", UID: "nais-" + teamName},
				{Title: teamName, UID: "legacy-uid"},
			}}, nil).Once()

		_, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err == nil || !strings.Contains(err.Error(), "another top-level folder") {
			t.Fatalf("expected title conflict, got %v", err)
		}
	})

	t.Run("rejects duplicate legacy titles across pages", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		hits := make([]*models.FolderSearchHit, limit)
		for i := range hits {
			hits[i] = &models.FolderSearchHit{Title: "another-team"}
		}
		hits[0] = &models.FolderSearchHit{Title: teamName, UID: "first-uid"}
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: hits}, nil).Once()
		folders.EXPECT().GetFolders(listParams(&secondPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: []*models.FolderSearchHit{
				{Title: teamName, UID: "second-uid"},
			}}, nil).Once()

		_, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err == nil || !strings.Contains(err.Error(), "2 top-level folders") {
			t.Fatalf("expected ambiguous legacy folder error, got %v", err)
		}
	})

	t.Run("creates a root folder when only a nested folder matches", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: []*models.FolderSearchHit{
				{Title: teamName, ParentUID: "parent"},
			}}, nil).Once()
		folders.EXPECT().CreateFolderWithParams(&grafanafolders.CreateFolderParams{
			Body: &models.CreateFolderCommand{
				Title:       teamName,
				UID:         "nais-" + teamName,
				Description: "Created by api-reconciler",
			},
			Context: ctx,
		}).Return(&grafanafolders.CreateFolderOK{Payload: &models.Folder{UID: "nais-" + teamName}}, nil).Once()

		uid, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err != nil || uid != "nais-"+teamName {
			t.Fatalf("expected nais-%s, got %q, %v", teamName, uid, err)
		}
	})

	t.Run("returns listing errors without creating a folder", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(nil, errors.New("listing failed")).Once()

		_, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err == nil || !strings.Contains(err.Error(), "listing failed") {
			t.Fatalf("expected listing error, got %v", err)
		}
	})

	t.Run("returns creation errors", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{}, nil).Once()
		folders.EXPECT().CreateFolderWithParams(&grafanafolders.CreateFolderParams{
			Body: &models.CreateFolderCommand{
				Title:       teamName,
				UID:         "nais-" + teamName,
				Description: "Created by api-reconciler",
			},
			Context: ctx,
		}).Return(nil, errors.New("creation failed")).Once()

		_, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err == nil || !strings.Contains(err.Error(), "creation failed") {
			t.Fatalf("expected creation error, got %v", err)
		}
	})

	t.Run("uses the full slug even when it starts with team-", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{}, nil).Once()
		folders.EXPECT().CreateFolderWithParams(&grafanafolders.CreateFolderParams{
			Body: &models.CreateFolderCommand{
				Title:       "team-rpa",
				UID:         "nais-team-rpa",
				Description: "Created by api-reconciler",
			},
			Context: ctx,
		}).Return(&grafanafolders.CreateFolderOK{Payload: &models.Folder{UID: "nais-team-rpa"}}, nil).Once()

		uid, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, "team-rpa")
		if err != nil || uid != "nais-team-rpa" {
			t.Fatalf("expected nais-team-rpa, got %q, %v", uid, err)
		}
	})

	t.Run("rejects slugs that exceed Grafana's UID limit", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{}, nil).Once()

		_, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, strings.Repeat("a", 36))
		if err == nil || !strings.Contains(err.Error(), "40-character limit") {
			t.Fatalf("expected UID length error, got %v", err)
		}
	})

	t.Run("rejects a mismatched creation response", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{}, nil).Once()
		folders.EXPECT().CreateFolderWithParams(&grafanafolders.CreateFolderParams{
			Body: &models.CreateFolderCommand{
				Title:       teamName,
				UID:         "nais-" + teamName,
				Description: "Created by api-reconciler",
			},
			Context: ctx,
		}).Return(&grafanafolders.CreateFolderOK{Payload: &models.Folder{UID: "unexpected-uid"}}, nil).Once()

		_, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err == nil || !strings.Contains(err.Error(), "did not return expected UID") {
			t.Fatalf("expected unexpected UID error, got %v", err)
		}
	})

	t.Run("rejects a folder without a UID", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: []*models.FolderSearchHit{{Title: teamName}}}, nil).Once()

		_, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err == nil || !strings.Contains(err.Error(), "no UID") {
			t.Fatalf("expected missing UID error, got %v", err)
		}
	})

	t.Run("returns folder read errors without updating it", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: []*models.FolderSearchHit{
				{Title: teamName, UID: "existing-uid"},
			}}, nil).Once()
		folders.EXPECT().GetFolderByUIDWithParams(&grafanafolders.GetFolderByUIDParams{
			FolderUID: "existing-uid", Context: ctx,
		}).Return(nil, errors.New("read failed")).Once()

		_, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err == nil || !strings.Contains(err.Error(), "read failed") {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("returns folder update errors", func(t *testing.T) {
		folders := NewMockFoldersClientService(t)
		folders.EXPECT().GetFolders(listParams(&firstPage)).
			Return(&grafanafolders.GetFoldersOK{Payload: []*models.FolderSearchHit{
				{Title: teamName, UID: "existing-uid"},
			}}, nil).Once()
		folders.EXPECT().GetFolderByUIDWithParams(&grafanafolders.GetFolderByUIDParams{
			FolderUID: "existing-uid", Context: ctx,
		}).Return(&grafanafolders.GetFolderByUIDOK{Payload: &models.Folder{Version: 2}}, nil).Once()
		folders.EXPECT().UpdateFolderWithParams(&grafanafolders.UpdateFolderParams{
			FolderUID: "existing-uid",
			Body: &models.UpdateFolderCommand{
				Description: "Reconciled by nais",
				Version:     2,
			},
			Context: ctx,
		}).Return(nil, errors.New("update failed")).Once()

		_, err := (&grafanaReconciler{folders: folders}).getOrCreateFolder(ctx, teamName)
		if err == nil || !strings.Contains(err.Error(), "update failed") {
			t.Fatalf("expected update error, got %v", err)
		}
	})
}
