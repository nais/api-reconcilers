package azure_group_reconciler

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/nais/api-reconcilers/internal/azureclient"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/microsoft"
)

const (
	reconcilerName = "azure:group"

	configClientSecret = "azure:client_secret"
	configClientID     = "azure:client_id"
	configTenantID     = "azure:tenant_id"

	azureGroupPrefix = "nais-team-"
)

type azureGroupReconciler struct {
	azureClient azureclient.Client
	domain      string
}

type reconcilerConfig struct {
	clientID     string
	clientSecret string
	tenantID     string
}

type OptFunc func(*azureGroupReconciler)

func WithAzureClient(client azureclient.Client) OptFunc {
	return func(r *azureGroupReconciler) {
		r.azureClient = client
	}
}

func New(ctx context.Context, domain string, apiClient *apiclient.APIClient, opts ...OptFunc) (reconcilers.Reconciler, error) {
	r := &azureGroupReconciler{
		domain: domain,
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.azureClient == nil {
		config, err := apiClient.Reconcilers().Config(ctx, &protoapi.ConfigReconcilerRequest{
			ReconcilerName: r.Name(),
		})
		if err != nil {
			return nil, err
		}

		rc := &reconcilerConfig{}
		for _, c := range config.Nodes {
			switch c.Key {
			case configClientSecret:
				rc.clientSecret = c.Value
			case configClientID:
				rc.clientID = c.Value
			case configTenantID:
				rc.tenantID = c.Value
			default:
				return nil, fmt.Errorf("unknown config key %q", c.Key)
			}
		}

		endpoint := microsoft.AzureADEndpoint(rc.tenantID)
		conf := clientcredentials.Config{
			ClientID:     rc.clientID,
			ClientSecret: rc.clientSecret,
			TokenURL:     endpoint.TokenURL,
			AuthStyle:    endpoint.AuthStyle,
			Scopes: []string{
				"https://graph.microsoft.com/.default",
			},
		}
		r.azureClient = azureclient.New(conf.Client(ctx))
	}

	return r, nil
}

func (r *azureGroupReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "Azure AD groups",
		Description: "Create and maintain Azure AD security groups for the Console teams.",
		MemberAware: true,
		Config: []*protoapi.ReconcilerConfigSpec{
			{
				Key:         configClientSecret,
				DisplayName: "Client secret",
				Description: "The client secret of the application registration.",
				Secret:      true,
			},
			{
				Key:         configClientID,
				DisplayName: "Client ID",
				Description: "The client ID of the application registration that Console will use when communicating with the Azure AD APIs. The application must have the following API permissions: Group.Create, GroupMember.ReadWrite.All.",
				Secret:      false,
			},
			{
				Key:         configTenantID,
				DisplayName: "Tenant ID",
				Description: "The ID of the Azure AD tenant.",
				Secret:      false,
			},
		},
	}
}

func (r *azureGroupReconciler) Name() string {
	return reconcilerName
}

func (r *azureGroupReconciler) Reconfigure(_ context.Context, _ *apiclient.APIClient, _ logrus.FieldLogger) error {
	// TODO: Handle configuration change
	return nil
}

func (r *azureGroupReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	state, err := r.loadState(ctx, client, naisTeam.Slug)
	if err != nil {
		return err
	}

	prefixedName := azureGroupPrefix + naisTeam.Slug
	azureGroup, created, err := r.azureClient.GetOrCreateGroup(ctx, state.groupID, prefixedName, naisTeam.Purpose)
	if err != nil {
		return err
	}

	log = log.WithField("azure_group_name", azureGroup.MailNickname)

	if created {
		id, _ := uuid.Parse(azureGroup.ID)
		if err := r.saveState(ctx, client, naisTeam.Slug, &azureState{groupID: id}); err != nil {
			return err
		}
	}

	if err := r.connectUsers(ctx, client, naisTeam.Slug, azureGroup, log); err != nil {
		return fmt.Errorf("add members to group: %w", err)
	}

	return nil
}

func (r *azureGroupReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	state, err := r.loadState(ctx, client, naisTeam.Slug)
	if err != nil {
		return err
	}

	if state.groupID == uuid.Nil {
		log.Warnf("missing group ID in reconciler state, assume team has already been deleted")
	} else if err := r.azureClient.DeleteGroup(ctx, state.groupID); err != nil {
		return fmt.Errorf("delete Azure AD group with ID %q for team %q: %w", state.groupID, naisTeam.Slug, err)
	}

	_, err = client.ReconcilerResources().Delete(ctx, &protoapi.DeleteReconcilerResourcesRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       naisTeam.Slug,
	})
	if err != nil {
		return err
	}

	return nil
}

func (r *azureGroupReconciler) connectUsers(ctx context.Context, client *apiclient.APIClient, teamSlug string, azureGroup *azureclient.Group, log logrus.FieldLogger) error {
	listTeamMembersResponse, err := client.Teams().Members(ctx, &protoapi.ListTeamMembersRequest{
		Slug: teamSlug,
	})
	if err != nil {
		return err
	}

	naisTeamMembers := listTeamMembersResponse.Nodes

	members, err := r.azureClient.ListGroupMembers(ctx, azureGroup)
	if err != nil {
		return fmt.Errorf("list existing members in Azure group %q: %s", azureGroup.MailNickname, err)
	}

	naisTeamUserMap := make(map[string]*protoapi.User)
	membersToRemove := remoteOnlyMembers(members, naisTeamMembers)
	for _, member := range membersToRemove {
		remoteEmail := strings.ToLower(member.Mail)
		log := log.WithField("remote_user_email", remoteEmail)
		if err := r.azureClient.RemoveMemberFromGroup(ctx, azureGroup, member); err != nil {
			log.WithError(err).Errorf("remove member from group in Azure")
			continue
		}

		if _, exists := naisTeamUserMap[remoteEmail]; !exists {
			resp, err := client.Users().Get(ctx, &protoapi.GetUserRequest{
				Email: remoteEmail,
			})
			if err != nil {
				log.WithError(err).Warnf("user does not exist in NAIS teams")
				continue
			}
			naisTeamUserMap[remoteEmail] = resp.User
		}
	}

	membersToAdd := localOnlyMembers(members, naisTeamMembers)
	for _, user := range membersToAdd {
		log := log.WithField("remote_user_email", user.Email)

		member, err := r.azureClient.GetUser(ctx, user.Email)
		if err != nil {
			log.WithError(err).Warnf("lookup user in Azure")
			continue
		}

		if err := r.azureClient.AddMemberToGroup(ctx, azureGroup, member); err != nil {
			log.WithError(err).Warnf("add member to group in Azure")
			continue
		}
	}

	return nil
}

// localOnlyMembers Given a list of Azure group members and a list of NAIS team members, return NAIS team users not
// present in the Azure group member list. The email address is used to compare objects.
func localOnlyMembers(azureGroupMembers []*azureclient.Member, naisTeamMembers []*protoapi.TeamMember) []*protoapi.User {
	localUserMap := make(map[string]*protoapi.User)
	for _, member := range naisTeamMembers {
		localUserMap[member.User.Email] = member.User
	}
	for _, member := range azureGroupMembers {
		delete(localUserMap, strings.ToLower(member.Mail))
	}
	localUsers := make([]*protoapi.User, 0)
	for _, user := range localUserMap {
		localUsers = append(localUsers, user)
	}
	return localUsers
}

// remoteOnlyMembers Given a list of Azure group members and a list of NAIS team members, return Azure group members
// not present in NAIS teams member list. The email address is used to compare objects.
func remoteOnlyMembers(azureGroupMembers []*azureclient.Member, naisTeamMembers []*protoapi.TeamMember) []*azureclient.Member {
	azureGroupMemberMap := make(map[string]*azureclient.Member)
	for _, member := range azureGroupMembers {
		azureGroupMemberMap[strings.ToLower(member.Mail)] = member
	}
	for _, member := range naisTeamMembers {
		delete(azureGroupMemberMap, member.User.Email)
	}
	azureGroupMembers = make([]*azureclient.Member, 0, len(azureGroupMemberMap))
	for _, member := range azureGroupMemberMap {
		azureGroupMembers = append(azureGroupMembers, member)
	}
	return azureGroupMembers
}
