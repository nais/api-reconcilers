package github_team_reconciler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/google/go-github/v50/github"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	strhelper "github.com/nais/api-reconcilers/internal/strings"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/shurcooL/githubv4"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"google.golang.org/api/impersonate"
)

var errGitHubUserNotFound = errors.New("GitHub user does not exist")

const reconcilerName = "github:team"

type OptFunc func(*githubTeamReconciler)

func WithTeamsService(teamsService TeamsService) OptFunc {
	return func(r *githubTeamReconciler) {
		r.teamsService = teamsService
	}
}

func WithGraphClient(graphClient GraphClient) OptFunc {
	return func(r *githubTeamReconciler) {
		r.graphClient = graphClient
	}
}

func New(ctx context.Context, org, authEndpoint, serviceAccountEmail string, opts ...OptFunc) (reconcilers.Reconciler, error) {
	r := &githubTeamReconciler{
		org: org,
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.teamsService == nil || r.graphClient == nil {
		ts, err := impersonate.IDTokenSource(ctx, impersonate.IDTokenConfig{
			Audience:        authEndpoint,
			TargetPrincipal: serviceAccountEmail,
		})
		if err != nil {
			return nil, err
		}

		httpClient := NewGitHubAuthClient(ctx, authEndpoint, ts)
		httpClient.Transport = otelhttp.NewTransport(httpClient.Transport)

		if r.teamsService == nil {
			r.teamsService = github.NewClient(httpClient).Teams
		}

		if r.graphClient == nil {
			r.graphClient = githubv4.NewClient(httpClient)
		}
	}

	return r, nil
}

func (r *githubTeamReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "GitHub teams",
		Description: "Create and maintain GitHub teams for the Console teams.",
		MemberAware: true,
	}
}

func (r *githubTeamReconciler) Name() string {
	return reconcilerName
}

func (r *githubTeamReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	st, err := r.loadState(ctx, client, naisTeam.Slug)
	if err != nil {
		return err
	}

	githubTeam, err := r.getOrCreateTeam(ctx, client, naisTeam)
	if err != nil {
		return fmt.Errorf("unable to get or create a GitHub team for team %q in system %q: %w", naisTeam.Slug, r.Name(), err)
	}

	if err := r.removeTeamIDPSync(ctx, *githubTeam.Slug); err != nil {
		return err
	}

	if err := r.syncTeamInfo(ctx, naisTeam, githubTeam); err != nil {
		return err
	}

	st.Repositories, err = r.getTeamRepositories(ctx, *githubTeam.Slug)
	if err != nil {
		return err
	}

	if err := r.saveState(ctx, client, naisTeam, *githubTeam.Slug, st); err != nil {
		return err
	}

	if err := r.connectUsers(ctx, client, naisTeam.Slug, githubTeam, log); err != nil {
		return err
	}

	return nil
}

func (r *githubTeamReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	if naisTeam.GithubTeamSlug == nil {
		log.Warnf("missing slug in reconciler state, unable to delete GitHub team")
		return nil
	}

	resp, err := r.teamsService.DeleteTeamBySlug(ctx, r.org, *naisTeam.GithubTeamSlug)
	if resp != nil {
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			// If not found, we consider the team already deleted
			return nil
		}
	}
	if err != nil {
		return fmt.Errorf("delete GitHub team %q for team %q: %w", *naisTeam.GithubTeamSlug, naisTeam.Slug, err)
	}

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected server response from GitHub: %q: %q", resp.Status, string(body))
	}

	return nil
}

func (r *githubTeamReconciler) syncTeamInfo(ctx context.Context, naisTeam *protoapi.Team, githubTeam *github.Team) error {
	if gitHubTeamIsUpdated(naisTeam, githubTeam) {
		return nil
	}

	slug := *githubTeam.Slug
	updatedGitHubTeam := github.NewTeam{
		Name:        slug,
		Description: &naisTeam.Purpose,
		Privacy:     new("closed"),
	}

	_, resp, err := r.teamsService.EditTeamBySlug(ctx, r.org, slug, updatedGitHubTeam, false)

	if resp == nil && err != nil {
		return fmt.Errorf("sync team info for GitHub team %q: %w", slug, err)
	}

	if resp.StatusCode >= 300 {
		return fmt.Errorf("sync team info for GitHub team %q: %s", slug, resp.Status)
	}

	return nil
}

func (r *githubTeamReconciler) removeTeamIDPSync(ctx context.Context, teamSlug string) error {
	grpList := github.IDPGroupList{
		Groups: make([]*github.IDPGroup, 0),
	}
	idpList, resp, err := r.teamsService.CreateOrUpdateIDPGroupConnectionsBySlug(ctx, r.org, teamSlug, grpList)
	if err != nil && strings.Contains(err.Error(), "team is not externally managed") {
		// Special case: org has not been configured for team IDP sync, which we don't want to treat as an error
		// More info: https://github.com/nais/teams-backend/issues/77
		return nil
	}

	if resp == nil && err != nil {
		return fmt.Errorf("unable to delete IDP sync from GitHub team %q: %w", teamSlug, err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unable to delete IDP sync for GitHub team %q: %s", teamSlug, resp.Status)
	}

	if len(idpList.Groups) > 0 {
		return fmt.Errorf("tried to delete IDP sync from GitHub team %q, but %d connections still remain", teamSlug, len(idpList.Groups))
	}

	return nil
}

func (r *githubTeamReconciler) getOrCreateTeam(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team) (*github.Team, error) {
	desiredTeamSlug := naisTeam.Slug
	if naisTeam.GithubTeamSlug != nil {
		desiredTeamSlug = *naisTeam.GithubTeamSlug
		existingTeam, resp, err := r.teamsService.GetTeamBySlug(ctx, r.org, desiredTeamSlug)
		if resp == nil && err != nil {
			return nil, fmt.Errorf("unable to fetch GitHub team %q: %w", desiredTeamSlug, err)
		}

		switch resp.StatusCode {
		case http.StatusNotFound:
			break
		case http.StatusOK:
			return existingTeam, nil
		default:
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("server error from GitHub: %s: %s", resp.Status, string(body))
		}
	}

	githubTeam, resp, err := r.teamsService.CreateTeam(ctx, r.org, github.NewTeam{
		Name:        desiredTeamSlug,
		Description: &naisTeam.Purpose,
		Privacy:     new("closed"),
	})
	err = httpError(http.StatusCreated, resp, err)
	if err != nil {
		return nil, fmt.Errorf("unable to create GitHub team: %w", err)
	}

	return githubTeam, nil
}

func (r *githubTeamReconciler) connectUsers(ctx context.Context, client *apiclient.APIClient, teamSlug string, githubTeam *github.Team, log logrus.FieldLogger) error {
	naisTeamMembers, err := reconcilers.GetTeamMembers(ctx, client.Teams(), teamSlug)
	if err != nil {
		return err
	}

	membersAccordingToGitHub, err := r.getTeamMembers(ctx, *githubTeam.Slug)
	if err != nil {
		return fmt.Errorf("list existing members in GitHub team %q: %w", *githubTeam.Slug, err)
	}

	gitHubUsersToApiUsers, err := r.mapSSOUsers(ctx, naisTeamMembers, log)
	if err != nil {
		return err
	}

	membersToRemove := remoteOnlyMembers(membersAccordingToGitHub, gitHubUsersToApiUsers)
	for _, gitHubUser := range membersToRemove {
		username := gitHubUser.GetLogin()
		resp, err := r.teamsService.RemoveTeamMembershipBySlug(ctx, r.org, *githubTeam.Slug, username)
		err = httpError(http.StatusNoContent, resp, err)
		if err != nil {
			log.WithError(err).Warnf("remove member %q from GitHub team %q", username, *githubTeam.Slug)
			continue
		}

		email, err := r.getEmailFromGitHubUsername(ctx, username)
		if err != nil {
			log.WithError(err).Warnf("get email from GitHub username %q for audit log purposes", username)
		}

		if email != nil {
			_, err = client.Users().Get(ctx, &protoapi.GetUserRequest{
				Email: *email,
			})
			if err != nil {
				log.WithError(err).Warnf("get NAIS teams user with email %q", *email)
				email = nil
			}
		}
	}

	membersToAdd := localOnlyMembers(gitHubUsersToApiUsers, membersAccordingToGitHub)
	for username := range membersToAdd {
		_, resp, err := r.teamsService.AddTeamMembershipBySlug(ctx, r.org, *githubTeam.Slug, username, &github.TeamAddTeamMembershipOptions{})
		if err := httpError(http.StatusOK, resp, err); err != nil {
			log.WithError(err).Warnf("add member %q to GitHub team %q", username, *githubTeam.Slug)
			continue
		}
	}

	return nil
}

// getTeamMembers Get all team members in a GitHub team using a paginated query
func (r *githubTeamReconciler) getTeamMembers(ctx context.Context, slug string) ([]*github.User, error) {
	const maxPerPage = 100
	opt := &github.TeamListTeamMembersOptions{
		ListOptions: github.ListOptions{
			PerPage: maxPerPage,
		},
	}

	allMembers := make([]*github.User, 0)
	for {
		members, resp, err := r.teamsService.ListTeamMembersBySlug(ctx, r.org, slug, opt)
		err = httpError(http.StatusOK, resp, err)
		if err != nil {
			return nil, err
		}
		allMembers = append(allMembers, members...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allMembers, nil
}

// localOnlyMembers Given a mapping of GitHub usernames to NAIS teams users, and a list of GitHub team members according
// to GitHub, return members only present in the mapping.
func localOnlyMembers(naisUsers map[string]*protoapi.User, membersAccordingToGitHub []*github.User) map[string]*protoapi.User {
	gitHubUsernameMap := make(map[string]*github.User)
	for _, gitHubUser := range membersAccordingToGitHub {
		gitHubUsernameMap[gitHubUser.GetLogin()] = gitHubUser
	}

	localOnly := make(map[string]*protoapi.User)
	for gitHubUsername, naisUser := range naisUsers {
		if _, exists := gitHubUsernameMap[gitHubUsername]; !exists {
			localOnly[gitHubUsername] = naisUser
		}
	}
	return localOnly
}

// remoteOnlyMembers Given a list of GitHub team members and a mapping of known GitHub usernames to NAIS teams users,
// return members not present in the mapping.
func remoteOnlyMembers(membersAccordingToGitHub []*github.User, naisUsers map[string]*protoapi.User) []*github.User {
	unknownMembers := make([]*github.User, 0)
	for _, member := range membersAccordingToGitHub {
		if _, exists := naisUsers[member.GetLogin()]; !exists {
			unknownMembers = append(unknownMembers, member)
		}
	}
	return unknownMembers
}

// mapSSOUsers Return a mapping of GitHub usernames to NAIS teams users. NAIS teams users with no matching GitHub user
// will be ignored.
func (r *githubTeamReconciler) mapSSOUsers(ctx context.Context, members []*protoapi.TeamMember, log logrus.FieldLogger) (map[string]*protoapi.User, error) {
	userMap := make(map[string]*protoapi.User)
	for _, member := range members {
		githubUsername, err := r.getGitHubUsernameFromEmail(ctx, member.User.Email)
		if errors.Is(err, errGitHubUserNotFound) {
			log.WithError(err).Warnf("no GitHub user for email: %q", member.User.Email)
			continue
		}
		if err != nil {
			return nil, err
		}
		userMap[*githubUsername] = member.User
	}

	return userMap, nil
}

// getGitHubUsernameFromEmail Look up a GitHub username from an SSO e-mail address connected to that user account.
func (r *githubTeamReconciler) getGitHubUsernameFromEmail(ctx context.Context, email string) (*string, error) {
	var query LookupGitHubSamlUserByEmail

	variables := map[string]any{
		"org":      githubv4.String(r.org),
		"username": githubv4.String(email),
	}

	err := r.graphClient.Query(ctx, &query, variables)
	if err != nil {
		return nil, err
	}

	nodes := query.Organization.SamlIdentityProvider.ExternalIdentities.Nodes
	if len(nodes) == 0 {
		return nil, errGitHubUserNotFound
	}

	username := string(nodes[0].User.Login)
	if len(username) == 0 {
		return nil, errGitHubUserNotFound
	}

	return &username, nil
}

// getEmailFromGitHubUsername Look up a GitHub username from an SSO e-mail address connected to that user account.
func (r *githubTeamReconciler) getEmailFromGitHubUsername(ctx context.Context, username string) (*string, error) {
	var query LookupGitHubSamlUserByGitHubUsername

	variables := map[string]any{
		"org":   githubv4.String(r.org),
		"login": githubv4.String(username),
	}

	err := r.graphClient.Query(ctx, &query, variables)
	if err != nil {
		return nil, err
	}

	nodes := query.Organization.SamlIdentityProvider.ExternalIdentities.Nodes
	if len(nodes) == 0 {
		return nil, errGitHubUserNotFound
	}

	email := strings.ToLower(string(nodes[0].SamlIdentity.Username))
	return &email, nil
}

func (r *githubTeamReconciler) getTeamRepositories(ctx context.Context, teamSlug string) ([]*GitHubRepository, error) {
	opts := &github.ListOptions{
		PerPage: 100,
	}

	allRepos := make([]*GitHubRepository, 0)
	for {
		repos, resp, err := r.teamsService.ListTeamReposBySlug(ctx, r.org, teamSlug, opts)
		err = httpError(http.StatusOK, resp, err)
		if err != nil {
			return nil, err
		}
		for _, repo := range repos {
			permissions := make([]*GitHubRepositoryPermission, 0)
			for name, granted := range repo.GetPermissions() {
				permissions = append(permissions, &GitHubRepositoryPermission{
					Name:    name,
					Granted: granted,
				})
			}

			sort.SliceStable(permissions, func(a, b int) bool {
				return permissions[a].Name < permissions[b].Name
			})

			allRepos = append(allRepos, &GitHubRepository{
				Name:        repo.GetFullName(),
				Permissions: permissions,
				Archived:    repo.GetArchived(),
				RoleName:    repo.GetRoleName(),
			})
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	sort.SliceStable(allRepos, func(a, b int) bool {
		return allRepos[a].Name < allRepos[b].Name
	})

	return allRepos, nil
}

// httpError Return an error if the response status code is not as expected, or if the passed err is already set to an
// error
func httpError(expected int, resp *github.Response, err error) error {
	if err != nil {
		return err
	}

	if resp == nil {
		return fmt.Errorf("no response")
	}

	if resp.StatusCode != expected {
		if resp.Body == nil {
			return errors.New("unknown error")
		}
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected response error %s: %s", resp.Status, string(body))
	}

	return nil
}

// gitHubTeamIsUpdated check if a GitHub team is updated compared to the NAIS team
func gitHubTeamIsUpdated(naisTeam *protoapi.Team, gitHubTeam *github.Team) bool {
	if naisTeam.Purpose != strhelper.WithFallback(gitHubTeam.Description, "") {
		return false
	}

	if gitHubTeam.GetPrivacy() != "closed" {
		return false
	}

	return true
}
