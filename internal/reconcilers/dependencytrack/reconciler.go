package dependencytrack_reconciler

import (
	"context"
	"fmt"
	"slices"

	"github.com/nais/api-reconcilers/internal/reconcilers"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/nais/dependencytrack/pkg/dependencytrack"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
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

func New(endpoint, username, password string, opts ...OptFunc) (reconcilers.Reconciler, error) {
	r := &reconciler{}

	for _, opt := range opts {
		opt(r)
	}

	if r.client == nil {
		if endpoint == "" || username == "" || password == "" {
			return nil, fmt.Errorf("no dependencytrack instances configured")
		}

		c, err := dependencytrack.NewClient(endpoint, username, password, logrus.WithField("client", "dependencytrack"), dependencytrack.WithHTTPClient(otelhttp.DefaultClient))
		if err != nil {
			return nil, fmt.Errorf("failed to create DependencyTrack client: %w", err)
		}
		r.client = c
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
	st, err := r.loadState(ctx, client, naisTeam.Slug)
	if err != nil {
		return err
	}

	teamMembers, err := reconcilers.GetTeamMembers(ctx, client.Teams(), naisTeam.Slug)
	if err != nil {
		return err
	}

	teamId, err := r.syncTeamAndUsers(ctx, naisTeam.Slug, teamMembers, st, log)
	if err != nil {
		return err
	}

	updatedState := &DependencyTrackState{
		TeamID: teamId,
		Members: func(members []*protoapi.TeamMember) []string {
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

func (r *reconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, _ logrus.FieldLogger) error {
	s, err := r.loadState(ctx, client, naisTeam.Slug)
	if err != nil {
		return err
	}

	if err := r.client.DeleteTeam(ctx, s.TeamID); err != nil {
		return err
	}

	if err := r.deleteState(ctx, client.Reconcilers(), naisTeam.Slug); err != nil {
		return err
	}

	return nil
}

func (r *reconciler) syncTeamAndUsers(ctx context.Context, teamSlug string, naisTeamMembers []*protoapi.TeamMember, st *DependencyTrackState, log logrus.FieldLogger) (string, error) {
	if st != nil && st.TeamID != "" {
		log.Debugf("team has existing state")
		for _, member := range naisTeamMembers {
			if !slices.Contains(st.Members, member.User.Email) {
				log := log.WithField("email", member.User.Email)
				log.Debugf("creating user in DependencyTrack")
				if err := r.client.CreateOidcUser(ctx, member.User.Email); err != nil {
					return "", err
				}

				log.Debugf("adding user to team in DependencyTrack")
				if err := r.client.AddToTeam(ctx, member.User.Email, st.TeamID); err != nil {
					return "", err
				}
			}
		}

		for _, email := range st.Members {
			if !inputMembersContains(naisTeamMembers, email) {
				log.WithField("email", email).Debugf("removing user from team in DependencyTrack")
				if err := r.client.DeleteUserMembership(ctx, st.TeamID, email); err != nil {
					return "", err
				}
			}
		}

		return st.TeamID, nil
	}

	log.Debugf("team does not yet exist in DependencyTrack, creating")
	team, err := r.createDependencyTrackTeam(ctx, teamSlug)
	if err != nil {
		return "", err
	}

	for _, member := range naisTeamMembers {
		log := log.WithField("email", member.User.Email)
		log.Debugf("creating user in DependencyTrack")
		if err := r.client.CreateOidcUser(ctx, member.User.Email); err != nil {
			return "", err
		}

		log.Debugf("adding user to team in DependencyTrack.")
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
