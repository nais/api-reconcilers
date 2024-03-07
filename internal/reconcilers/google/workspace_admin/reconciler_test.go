package google_workspace_admin_reconciler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	google_workspace_admin_reconciler "github.com/nais/api-reconcilers/internal/reconcilers/google/workspace_admin"
	"github.com/nais/api-reconcilers/internal/test"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	admin_directory_v1 "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
	"k8s.io/utils/ptr"
)

func TestReconcile(t *testing.T) {
	ctx := context.Background()

	const (
		gkeSecurityGroup    = "gke-security-groups@example.com"
		teamSlug            = "my-team"
		teamPurpose         = "some purpose"
		serviceAccountEmail = "sa@example.com"
		subjectEmail        = "admin-user@example.com"
		tenantDomain        = "example.com"
	)

	naisTeam := &protoapi.Team{
		Slug:    teamSlug,
		Purpose: teamPurpose,
	}

	log, _ := logrustest.NewNullLogger()

	t.Run("empty state, create group", func(t *testing.T) {
		naisTeamMember1 := &protoapi.User{Email: "user1@example.com"}
		naisTeamMember2 := &protoapi.User{Email: "user2@example.com"}
		addMe := &protoapi.User{Email: "add-me@example.com"}
		removeMe := &protoapi.User{Email: "remove-me@example.com"}

		expectedGoogleGroupEmail := "nais-team-my-team@example.com"
		googleGroupId := uuid.New().String()
		googleUserId1 := uuid.New().String()
		googleUserId2 := uuid.New().String()
		googleUserId4 := uuid.New().String()

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Teams.EXPECT().
			Members(mock.Anything, &protoapi.ListTeamMembersRequest{Slug: teamSlug, Limit: 100, Offset: 0}).
			Return(&protoapi.ListTeamMembersResponse{Nodes: []*protoapi.TeamMember{
				{User: naisTeamMember1},
				{User: naisTeamMember2},
				{User: addMe},
			}}, nil).
			Once()
		mockServer.Users.EXPECT().
			Get(mock.Anything, &protoapi.GetUserRequest{Email: removeMe.Email}).
			Return(&protoapi.GetUserResponse{User: removeMe}, nil).
			Once()
		mockServer.Teams.EXPECT().
			SetTeamExternalReferences(mock.Anything, &protoapi.SetTeamExternalReferencesRequest{Slug: teamSlug, GoogleGroupEmail: ptr.To(expectedGoogleGroupEmail)}).
			Return(&protoapi.SetTeamExternalReferencesResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(req *protoapi.CreateAuditLogsRequest) bool {
				return req.Action == "google:workspace-admin:create" && req.ReconcilerName == "google:workspace-admin"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(req *protoapi.CreateAuditLogsRequest) bool {
				return req.Action == "google:workspace-admin:delete-member" && req.ReconcilerName == "google:workspace-admin"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(req *protoapi.CreateAuditLogsRequest) bool {
				return req.Action == "google:workspace-admin:add-member" && req.ReconcilerName == "google:workspace-admin"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(req *protoapi.CreateAuditLogsRequest) bool {
				return req.Action == "google:workspace-admin:add-to-gke-security-group" && req.ReconcilerName == "google:workspace-admin"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		ts := test.HttpServerWithHandlers(t, []http.HandlerFunc{
			// create group
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got %q", r.Method)
				}

				googleGroup := admin_directory_v1.Group{}
				_ = json.NewDecoder(r.Body).Decode(&googleGroup)
				if googleGroup.Email != expectedGoogleGroupEmail {
					t.Errorf("expected email %q, got %q", expectedGoogleGroupEmail, googleGroup.Email)
				}

				googleGroup.Id = googleGroupId
				rsp, _ := googleGroup.MarshalJSON()
				_, _ = w.Write(rsp)
			},

			// list existing members
			func(w http.ResponseWriter, r *http.Request) {
				members := admin_directory_v1.Members{
					Members: []*admin_directory_v1.Member{
						{Id: googleUserId1, Email: "user1@example.com"},     // is already a team member
						{Id: googleUserId2, Email: "user2@example.com"},     // is already a team member
						{Id: googleUserId4, Email: "remove-me@example.com"}, // is not a team member, will be removed from the Google group
					},
				}
				rsp, _ := members.MarshalJSON()
				_, _ = w.Write(rsp)
			},

			// delete member
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected HTTP DELETE, got %q", r.Method)
				}

				if contains := "/groups/" + googleGroupId + "/members/" + googleUserId4; !strings.Contains(r.URL.Path, contains) {
					t.Errorf("expected %q to contain %q", r.URL.Path, contains)
				}
			},

			// add missing member
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got %q", r.Method)
				}

				addedMember := admin_directory_v1.Member{}
				_ = json.NewDecoder(r.Body).Decode(&addedMember)

				if addedMember.Email != addMe.Email {
					t.Errorf("expected email %q, got %q", addMe.Email, addedMember.Email)
				}

				rsp, _ := addedMember.MarshalJSON()
				_, _ = w.Write(rsp)
			},

			// add to GKE security group
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected HTTP POST, got %q", r.Method)
				}

				if contains := "/groups/" + gkeSecurityGroup + "/members"; !strings.Contains(r.URL.Path, contains) {
					t.Errorf("expected %q to contain %q", r.URL.Path, contains)
				}

				addedMember := admin_directory_v1.Member{}
				_ = json.NewDecoder(r.Body).Decode(&addedMember)

				if addedMember.Email != expectedGoogleGroupEmail {
					t.Errorf("expected email %q, got %q", expectedGoogleGroupEmail, addedMember.Email)
				}

				rsp, _ := addedMember.MarshalJSON()
				_, _ = w.Write(rsp)
			},
		})
		defer ts.Close()

		service, _ := admin_directory_v1.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(ts.URL))

		reconciler, err := google_workspace_admin_reconciler.New(ctx, serviceAccountEmail, subjectEmail, tenantDomain, google_workspace_admin_reconciler.WithAdminDirectoryService(service))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Reconcile(ctx, apiClient, naisTeam, log); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func Test_Delete(t *testing.T) {
	ctx := context.Background()

	const (
		teamSlug            = "my-team"
		teamPurpose         = "some purpose"
		serviceAccountEmail = "sa@example.com"
		subjectEmail        = "admin-user@example.com"
		tenantDomain        = "example.com"
		googleGroupEmail    = "nais-team-my-team@example.com"
	)

	t.Run("no group email in state", func(t *testing.T) {
		log, hook := logrustest.NewNullLogger()

		naisTeam := &protoapi.Team{
			Slug:    teamSlug,
			Purpose: teamPurpose,
		}

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Reconcilers.EXPECT().
			DeleteState(mock.Anything, &protoapi.DeleteReconcilerStateRequest{TeamSlug: teamSlug, ReconcilerName: "google:workspace-admin"}).
			Return(&protoapi.DeleteReconcilerStateResponse{}, nil).
			Once()

		service, closer := getAdminDirectoryServiceAndClient(t, ctx, nil)
		defer closer()

		reconciler, err := google_workspace_admin_reconciler.New(ctx, serviceAccountEmail, subjectEmail, tenantDomain, google_workspace_admin_reconciler.WithAdminDirectoryService(service))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Delete(ctx, apiClient, naisTeam, log); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(hook.Entries) != 1 {
			t.Fatalf("expected 1 log entry, got %d", len(hook.Entries))
		}

		if lvl := hook.LastEntry().Level; lvl != logrus.WarnLevel {
			t.Errorf("expected log level %q, got %q", logrus.WarnLevel, lvl)
		}

		if msg := hook.LastEntry().Message; !strings.Contains(msg, "missing group email in team") {
			t.Errorf("expected log message to contain %q, got %q", "missing group email in team", msg)
		}
	})

	t.Run("Google API failure", func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()
		naisTeam := &protoapi.Team{
			Slug:             teamSlug,
			Purpose:          teamPurpose,
			GoogleGroupEmail: ptr.To(googleGroupEmail),
		}
		googleAdminService, closer := getAdminDirectoryServiceAndClient(t, ctx, []http.HandlerFunc{
			// delete group failure
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("expected HTTP DELETE, got %q", r.Method)
				}

				if contains := "/groups/" + googleGroupEmail; !strings.Contains(r.URL.Path, contains) {
					t.Errorf("expected %q to contain %q", r.URL.Path, contains)
				}

				w.WriteHeader(http.StatusBadRequest)
			},
		})
		defer closer()

		apiClient, _ := apiclient.NewMockClient(t)

		reconciler, err := google_workspace_admin_reconciler.New(ctx, serviceAccountEmail, subjectEmail, tenantDomain, google_workspace_admin_reconciler.WithAdminDirectoryService(googleAdminService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Delete(ctx, apiClient, naisTeam, log); !strings.Contains(err.Error(), "delete Google directory group") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("successful delete", func(t *testing.T) {
		log, hook := logrustest.NewNullLogger()

		naisTeam := &protoapi.Team{
			Slug:             teamSlug,
			Purpose:          teamPurpose,
			GoogleGroupEmail: ptr.To(googleGroupEmail),
		}

		googleAdminService, closer := getAdminDirectoryServiceAndClient(t, ctx, []http.HandlerFunc{
			// delete group
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
		})
		defer closer()

		apiClient, mockServer := apiclient.NewMockClient(t)
		mockServer.Reconcilers.EXPECT().
			DeleteState(mock.Anything, &protoapi.DeleteReconcilerStateRequest{TeamSlug: teamSlug, ReconcilerName: "google:workspace-admin"}).
			Return(&protoapi.DeleteReconcilerStateResponse{}, nil).
			Once()
		mockServer.AuditLogs.EXPECT().
			Create(mock.Anything, mock.MatchedBy(func(req *protoapi.CreateAuditLogsRequest) bool {
				return req.Action == "google:workspace-admin:delete" && req.ReconcilerName == "google:workspace-admin"
			})).
			Return(&protoapi.CreateAuditLogsResponse{}, nil).
			Once()

		reconciler, err := google_workspace_admin_reconciler.New(ctx, serviceAccountEmail, subjectEmail, tenantDomain, google_workspace_admin_reconciler.WithAdminDirectoryService(googleAdminService))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := reconciler.Delete(ctx, apiClient, naisTeam, log); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(hook.Entries) != 0 {
			t.Fatalf("expected no log entries, got %d", len(hook.Entries))
		}
	})
}

func getAdminDirectoryServiceAndClient(t *testing.T, ctx context.Context, handlers []http.HandlerFunc) (service *admin_directory_v1.Service, closer func()) {
	ts := test.HttpServerWithHandlers(t, handlers)
	closer = ts.Close
	service, _ = admin_directory_v1.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(ts.URL))
	return
}
