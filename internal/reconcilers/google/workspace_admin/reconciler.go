package google_workspace_admin_reconciler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/nais/api-reconcilers/internal/google_token_source"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	admin_directory_v1 "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

const (
	reconcilerName    = "google:workspace-admin"
	googleGroupPrefix = "nais-team-"
)

type googleWorkspaceAdminReconciler struct {
	adminDirectoryService *admin_directory_v1.Service
	tenantDomain          string
}

type OptFunc func(*googleWorkspaceAdminReconciler)

func WithAdminDirectoryService(service *admin_directory_v1.Service) OptFunc {
	return func(r *googleWorkspaceAdminReconciler) {
		r.adminDirectoryService = service
	}
}

func New(ctx context.Context, serviceAccountEmail, subjectEmail, tenantDomain string, opts ...OptFunc) (reconcilers.Reconciler, error) {
	r := &googleWorkspaceAdminReconciler{
		tenantDomain: tenantDomain,
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.adminDirectoryService == nil {
		ts, err := google_token_source.WorkspaceAdminTokenSource(ctx, serviceAccountEmail, subjectEmail)
		if err != nil {
			return nil, fmt.Errorf("get delegated token source: %w", err)
		}

		service, err := admin_directory_v1.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			return nil, fmt.Errorf("retrieve directory client: %w", err)
		}

		r.adminDirectoryService = service
	}

	return r, nil
}

func (r *googleWorkspaceAdminReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "Google workspace group",
		Description: "Create and maintain Google workspace groups for the Console teams.",
		MemberAware: true,
	}
}

func (r *googleWorkspaceAdminReconciler) Name() string {
	return reconcilerName
}

func (r *googleWorkspaceAdminReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	googleGroup, err := r.getOrCreateGroup(ctx, naisTeam)
	if err != nil {
		return fmt.Errorf("unable to get or create a Google Workspace group for team %q: %w", naisTeam.Slug, err)
	}

	if naisTeam.GoogleGroupEmail == nil || *naisTeam.GoogleGroupEmail != googleGroup.Email {
		_, err := client.Teams().SetTeamExternalReferences(ctx, &protoapi.SetTeamExternalReferencesRequest{
			Slug:             naisTeam.Slug,
			GoogleGroupEmail: &googleGroup.Email,
		})
		if err != nil {
			return fmt.Errorf("set Google group email for team %q: %w", naisTeam.Slug, err)
		}
	}

	if err := r.syncGroupInfo(ctx, naisTeam, googleGroup); err != nil {
		return err
	}

	if err := r.connectUsers(ctx, client, naisTeam.Slug, googleGroup, log); err != nil {
		return fmt.Errorf("add members to group: %w", err)
	}

	if err := r.addToGKESecurityGroup(ctx, client, naisTeam, googleGroup); err != nil {
		return err
	}

	return nil
}

func (r *googleWorkspaceAdminReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	if naisTeam.GoogleGroupEmail == nil {
		log.Warnf("missing group email in team, assume team has already been deleted")
		return nil
	}

	if err := r.adminDirectoryService.Groups.Delete(*naisTeam.GoogleGroupEmail).Context(ctx).Do(); err != nil {
		var googleError *googleapi.Error
		ok := errors.As(err, &googleError)
		if ok && googleError.Code == http.StatusNotFound {
			// Group does not exist, assume it has already been deleted
			return nil
		}
		return fmt.Errorf("delete Google directory group with email %q for team %q: %w", *naisTeam.GoogleGroupEmail, naisTeam.Slug, err)
	}

	return nil
}

func (r *googleWorkspaceAdminReconciler) getOrCreateGroup(ctx context.Context, naisTeam *protoapi.Team) (*admin_directory_v1.Group, error) {
	if naisTeam.GoogleGroupEmail != nil {
		googleGroup, err := r.adminDirectoryService.Groups.Get(*naisTeam.GoogleGroupEmail).Context(ctx).Do()
		if err != nil {
			return nil, err
		}
		return googleGroup, err
	}

	groupKey := googleGroupPrefix + naisTeam.Slug
	newGroup := &admin_directory_v1.Group{
		Email:       groupKey + "@" + r.tenantDomain,
		Name:        groupKey,
		Description: naisTeam.Purpose,
	}
	createdGroup, err := r.adminDirectoryService.Groups.Insert(newGroup).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("unable to create Google Directory group: %w", err)
	}

	return createdGroup, nil
}

// getGoogleGroupMembers Get all members of a Google Workspace Group
func getGoogleGroupMembers(ctx context.Context, service *admin_directory_v1.MembersService, groupID string) ([]*admin_directory_v1.Member, error) {
	members := make([]*admin_directory_v1.Member, 0)
	callback := func(fragments *admin_directory_v1.Members) error {
		members = append(members, fragments.Members...)
		return nil
	}
	err := service.
		List(groupID).
		Context(ctx).
		Pages(ctx, callback)
	if err != nil {
		return nil, fmt.Errorf("list existing members in Google Directory group: %w", err)
	}

	return members, nil
}

func (r *googleWorkspaceAdminReconciler) connectUsers(ctx context.Context, client *apiclient.APIClient, teamSlug string, googleGroup *admin_directory_v1.Group, log logrus.FieldLogger) error {
	log = log.
		WithField("google_group_email", googleGroup.Email).
		WithField("google_group_id", googleGroup.Id)

	naisTeamMembers, err := reconcilers.GetTeamMembers(ctx, client.Teams(), teamSlug)
	if err != nil {
		return err
	}

	membersAccordingToGoogle, err := getGoogleGroupMembers(ctx, r.adminDirectoryService.Members, googleGroup.Id)
	if err != nil {
		return fmt.Errorf("list existing members in Google Directory group: %w", err)
	}

	naisTeamUserMap := make(map[string]*protoapi.User)
	membersToRemove := remoteOnlyMembers(membersAccordingToGoogle, naisTeamMembers)
	for _, member := range membersToRemove {
		remoteEmail := strings.ToLower(member.Email)
		log := log.WithField("remote_user_email", remoteEmail)

		if err := r.adminDirectoryService.Members.Delete(googleGroup.Id, member.Id).Context(ctx).Do(); err != nil {
			log.WithError(err).Errorf("remove member from Google Directory group")
			continue
		}

		if _, exists := naisTeamUserMap[remoteEmail]; !exists {
			resp, err := client.Users().Get(ctx, &protoapi.GetUserRequest{
				Email: remoteEmail,
			})
			if err != nil {
				log.WithError(err).Warnf("user does not exist in NAIS teams")
			} else {
				naisTeamUserMap[remoteEmail] = resp.User
			}
		}
	}

	membersToAdd := localOnlyMembers(membersAccordingToGoogle, naisTeamMembers)
	for _, user := range membersToAdd {
		log := log.WithField("remote_user_email", user.Email)

		member := &admin_directory_v1.Member{
			Email: user.Email,
		}

		if _, err := r.adminDirectoryService.Members.Insert(googleGroup.Id, member).Context(ctx).Do(); err != nil {
			log.WithError(err).Errorf("add member to Google Directory group")
		}
	}

	return nil
}

func (r *googleWorkspaceAdminReconciler) addToGKESecurityGroup(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, googleGroup *admin_directory_v1.Group) error {
	groupKey := "gke-security-groups@" + r.tenantDomain

	member := &admin_directory_v1.Member{
		Email: googleGroup.Email,
	}

	if _, err := r.adminDirectoryService.Members.Insert(groupKey, member).Context(ctx).Do(); err != nil {
		var googleError *googleapi.Error
		ok := errors.As(err, &googleError)
		if ok && googleError.Code == http.StatusConflict {
			return nil
		}
		return fmt.Errorf("add group %q to GKE security group %q: %s", member.Email, groupKey, err)
	}

	return nil
}

func (r *googleWorkspaceAdminReconciler) syncGroupInfo(ctx context.Context, naisTeam *protoapi.Team, googleGroup *admin_directory_v1.Group) error {
	if naisTeam.Purpose == googleGroup.Description {
		return nil
	}

	googleGroup.Description = naisTeam.Purpose
	googleGroup.ForceSendFields = []string{"Description"}

	if _, err := r.adminDirectoryService.Groups.Patch(googleGroup.Id, googleGroup).Context(ctx).Do(); err != nil {
		return err
	}

	return nil
}

// remoteOnlyMembers Given a list of Google group members and a list of NAIS team members, return Google group members
// not present in NAIS team member list.
func remoteOnlyMembers(googleGroupMembers []*admin_directory_v1.Member, naisTeamMembers []*protoapi.TeamMember) []*admin_directory_v1.Member {
	googleGroupMemberMap := make(map[string]*admin_directory_v1.Member)
	for _, member := range googleGroupMembers {
		googleGroupMemberMap[strings.ToLower(member.Email)] = member
	}
	for _, member := range naisTeamMembers {
		delete(googleGroupMemberMap, member.User.Email)
	}
	googleGroupMembers = make([]*admin_directory_v1.Member, 0, len(googleGroupMemberMap))
	for _, member := range googleGroupMemberMap {
		googleGroupMembers = append(googleGroupMembers, member)
	}
	return googleGroupMembers
}

// localOnlyMembers Given a list of Google group members and a list of NAIS team members, return members not present in
// members directory.
func localOnlyMembers(googleGroupMembers []*admin_directory_v1.Member, naisTeamMembers []*protoapi.TeamMember) []*protoapi.User {
	localUserMap := make(map[string]*protoapi.User)
	for _, member := range naisTeamMembers {
		localUserMap[member.User.Email] = member.User
	}
	for _, member := range googleGroupMembers {
		delete(localUserMap, strings.ToLower(member.Email))
	}
	users := make([]*protoapi.User, 0)
	for _, user := range localUserMap {
		users = append(users, user)
	}
	return users
}
