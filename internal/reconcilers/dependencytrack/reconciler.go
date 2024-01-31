package dependencytrack_reconciler

import (
	"context"
	"fmt"
	"slices"

	"github.com/nais/api-reconcilers/internal/reconcilers"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	dependencytrack "github.com/nais/dependencytrack/pkg/client"
	"github.com/sirupsen/logrus"
)

type reconciler struct {
	client dependencytrack.Client
}

const reconcilerName = "nais:dependencytrack"

type OptFunc func(*reconciler)

func WithDependencyTrackClient(client dependencytrack.Client) OptFunc {
	return func(r *reconciler) {
		r.client = client
	}
}

func New(ctx context.Context, endpoint, username, password string, opts ...OptFunc) (reconcilers.Reconciler, error) {
	r := &reconciler{}

	for _, opt := range opts {
		opt(r)
	}

	if r.client == nil {
		if endpoint == "" || username == "" || password == "" {
			return nil, fmt.Errorf("no dependencytrack instances configured")
		}

		r.client = dependencytrack.New(endpoint, username, password)
	}

	return r, nil
}

func (r *reconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "DependencyTrack",
		Description: "Create teams and users in DependencyTrack",
		MemberAware: true,
	}
}

func (r *reconciler) Name() string {
	return reconcilerName
}

func (r *reconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	state, err := r.loadState(ctx, client, naisTeam.Slug)
	if err != nil {
		return err
	}

	teamMembers, err := reconcilers.GetTeamMembers(ctx, client.Teams(), naisTeam.Slug)
	if err != nil {
		return err
	}

	teamId, err := r.syncTeamAndUsers(ctx, naisTeam.Slug, teamMembers, state)
	if err != nil {
		return err
	}

	updatedState := &dependencyTrackState{
		teamID: teamId,
		members: func(members []*protoapi.TeamMember) []string {
			emails := make([]string, len(members))
			for i, member := range members {
				emails[i] = member.User.Email
			}
			return emails
		}(teamMembers),
	}

	if err := r.saveState(ctx, client, naisTeam.Slug, updatedState); err != nil {
		return err
	}

	return nil
}

func (r *reconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	state, err := r.loadState(ctx, client, naisTeam.Slug)
	if err != nil {
		return err
	}

	if err := r.client.DeleteTeam(ctx, state.teamID); err != nil {
		return err
	}

	if err := r.deleteState(ctx, client.ReconcilerResources(), naisTeam.Slug); err != nil {
		return err
	}

	return nil
}

func (r *reconciler) syncTeamAndUsers(ctx context.Context, teamSlug string, naisTeamMembers []*protoapi.TeamMember, state *dependencyTrackState) (string, error) {
	if state != nil && state.teamID != "" {
		for _, member := range naisTeamMembers {
			if !slices.Contains(state.members, member.User.Email) {
				if err := r.client.CreateOidcUser(ctx, member.User.Email); err != nil {
					return "", err
				}

				if err := r.client.AddToTeam(ctx, member.User.Email, state.teamID); err != nil {
					return "", err
				}
			}
		}

		for _, email := range state.members {
			if !inputMembersContains(naisTeamMembers, email) {
				if err := r.client.DeleteUserMembership(ctx, state.teamID, email); err != nil {
					return "", err
				}
			}
		}

		return state.teamID, nil
	}

	team, err := r.createDependencyTrackTeam(ctx, teamSlug)
	if err != nil {
		return "", err
	}

	for _, member := range naisTeamMembers {
		if err := r.client.CreateOidcUser(ctx, member.User.Email); err != nil {
			return "", err
		}
		if err := r.client.AddToTeam(ctx, member.User.Email, team.Uuid); err != nil {
			return "", err
		}
	}

	return team.Uuid, nil
}

func (r *reconciler) createDependencyTrackTeam(ctx context.Context, teamSlug string) (*dependencytrack.Team, error) {
	permissions := []dependencytrack.Permission{
		dependencytrack.ViewPortfolioPermission,
		dependencytrack.ViewVulnerabilityPermission,
		dependencytrack.ViewPolicyViolationPermission,
	}

	if teamIsNaisTeam(teamSlug) {
		extraPermissions := []dependencytrack.Permission{
			dependencytrack.AccessManagementPermission,
			dependencytrack.PolicyManagementPermission,
			dependencytrack.PolicyViolationAnalysisPermission,
			dependencytrack.SystemConfigurationPermission,
		}
		permissions = append(permissions, extraPermissions...)
	}

	team, err := r.client.CreateTeam(ctx, teamSlug, permissions)
	if err != nil {
		return nil, err
	}

	return team, err
}

func inputMembersContains(naisTeamMembers []*protoapi.TeamMember, email string) bool {
	for _, member := range naisTeamMembers {
		if member.User.Email == email {
			return true
		}
	}
	return false
}

func teamIsNaisTeam(teamSlug string) bool {
	return teamSlug == "nais" || teamSlug == "aura"
}
