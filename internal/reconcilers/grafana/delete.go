package grafana_reconciler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	grafanafolders "github.com/grafana/grafana-openapi-client-go/client/folders"
	grafanaprovisioning "github.com/grafana/grafana-openapi-client-go/client/provisioning"
	grafanateams "github.com/grafana/grafana-openapi-client-go/client/teams"
	"github.com/grafana/grafana-openapi-client-go/models"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
)

func grafanaResourceNotFound(err error) bool {
	var response interface{ IsCode(int) bool }
	return errors.As(err, &response) && response.IsCode(http.StatusNotFound)
}

func (r *grafanaReconciler) Delete(ctx context.Context, _ *apiclient.APIClient, team *protoapi.Team, log logrus.FieldLogger) error {
	r.alertingMu.Lock()
	defer r.alertingMu.Unlock()

	slug := team.GetSlug()
	if slug == "" {
		return fmt.Errorf("cannot delete Grafana resources without a team slug")
	}
	if r.teams == nil || r.folders == nil || r.provisioning == nil {
		return fmt.Errorf("cannot delete Grafana resources for team %s: teams, folders and provisioning clients are required", slug)
	}
	teams, err := r.deletionTeams(ctx, slug)
	if err != nil {
		return err
	}
	folderUID, err := r.deletionFolder(ctx, slug)
	if err != nil {
		return err
	}
	policy, err := r.provisioning.GetPolicyTree()
	if err != nil {
		return fmt.Errorf("getting policy tree before deleting team %s: %w", slug, err)
	}
	if policy == nil || policy.Payload == nil {
		return fmt.Errorf("getting policy tree before deleting team %s: empty response", slug)
	}
	receivers := make(map[string]bool)
	planned, err := removeTeamNotificationRoutes(policy.Payload, slug, receivers)
	if err != nil {
		return err
	}
	points, err := r.provisioning.GetContactpoints(grafanaprovisioning.NewGetContactpointsParamsWithContext(ctx))
	if err != nil {
		return fmt.Errorf("getting contact points before deleting team %s: %w", slug, err)
	}
	if points == nil {
		return fmt.Errorf("getting contact points before deleting team %s: empty response", slug)
	}
	var owned []*models.EmbeddedContactPoint
	for _, point := range points.Payload {
		if point == nil || point.Name == "" || point.UID == "" {
			return fmt.Errorf("invalid contact point while deleting team %s", slug)
		}
		if deletionContactPointOwned(point.Name, slug, teams) {
			owned = append(owned, point)
		} else if receivers[point.Name] {
			log.Warnf("Keeping legacy or shared contact point %q while deleting team %s; manual ownership review required", point.Name, slug)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if folderUID != "" {
		force := true
		_, err := r.folders.DeleteFolder(&grafanafolders.DeleteFolderParams{
			FolderUID: folderUID, ForceDeleteRules: &force, Context: ctx,
		})
		if err != nil && !grafanaResourceNotFound(err) {
			return fmt.Errorf("deleting folder %s and its contents: %w", folderUID, err)
		}
		log.Infof("Deleted team folder %s and its contents", folderUID)
	}
	latest, err := r.provisioning.GetPolicyTree()
	if err != nil {
		return fmt.Errorf("rechecking policy tree before deleting team %s routes: %w", slug, err)
	}
	if latest == nil || latest.Payload == nil {
		return fmt.Errorf("rechecking policy tree before deleting team %s routes: empty response", slug)
	}
	if !reflect.DeepEqual(latest.Payload, policy.Payload) {
		return fmt.Errorf("notification policy tree changed while deleting team %s; refusing to overwrite external changes", slug)
	}
	if !reflect.DeepEqual(planned, policy.Payload) {
		planned.Provenance = models.Provenance("api")
		_, err := r.provisioning.PutPolicyTree(&grafanaprovisioning.PutPolicyTreeParams{Body: planned, Context: ctx})
		if err != nil {
			return fmt.Errorf("removing notification policies for team %s: %w", slug, err)
		}
	}
	references := make(map[string]bool)
	current, err := r.provisioning.GetPolicyTree()
	if err != nil {
		return fmt.Errorf("checking remaining contact point references: %w", err)
	}
	if current == nil || current.Payload == nil {
		return fmt.Errorf("checking remaining contact point references: empty response")
	}
	if !reflect.DeepEqual(current.Payload, planned) {
		return fmt.Errorf("notification policy tree changed after removing team %s routes; refusing to delete contact points", slug)
	}
	if err := notificationRouteReceivers(current.Payload, references); err != nil {
		return err
	}
	rules, err := r.provisioning.GetAlertRules()
	if err != nil {
		return fmt.Errorf("checking direct alert rule receivers: %w", err)
	}
	if rules == nil {
		return fmt.Errorf("checking direct alert rule receivers: empty response")
	}
	for _, rule := range rules.Payload {
		if rule == nil {
			return fmt.Errorf("null alert rule while checking contact point references")
		}
		if rule.NotificationSettings != nil {
			if rule.NotificationSettings.Receiver == nil || *rule.NotificationSettings.Receiver == "" {
				return fmt.Errorf("alert rule %s has invalid direct notification settings", rule.UID)
			}
			references[*rule.NotificationSettings.Receiver] = true
		}
	}
	for _, point := range owned {
		if references[point.Name] {
			log.Warnf("Keeping shared contact point %q while deleting team %s; still referenced outside the deleted team policies and folder", point.Name, slug)
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := r.provisioning.DeleteContactpointsWithParams(&grafanaprovisioning.DeleteContactpointsParams{UID: point.UID, Context: ctx})
		if err != nil && !grafanaResourceNotFound(err) {
			return fmt.Errorf("deleting contact point %q (%s): %w", point.Name, point.UID, err)
		}
	}
	for _, existing := range teams {
		if *existing.Name != slug {
			continue
		}
		if existing.ID == nil {
			return fmt.Errorf("team %s has no ID", slug)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := r.teams.DeleteTeamByID(strconv.FormatInt(*existing.ID, 10))
		if err != nil && !grafanaResourceNotFound(err) {
			return fmt.Errorf("deleting Grafana team %s: %w", slug, err)
		}
	}
	return nil
}

func (r *grafanaReconciler) deletionTeams(ctx context.Context, slug string) ([]*models.TeamDTO, error) {
	var teams []*models.TeamDTO
	limit := int64(1000)
	for page := int64(1); ; page++ {
		resp, err := r.teams.SearchTeams(&grafanateams.SearchTeamsParams{Query: &slug, Page: &page, Perpage: &limit, Context: ctx})
		if err != nil {
			return nil, fmt.Errorf("searching Grafana teams before deleting %s: %w", slug, err)
		}
		if resp == nil || resp.Payload == nil {
			return nil, fmt.Errorf("searching Grafana teams before deleting %s: empty response", slug)
		}
		for _, team := range resp.Payload.Teams {
			if team == nil || team.Name == nil || *team.Name == "" {
				return nil, fmt.Errorf("invalid Grafana team while deleting %s", slug)
			}
			if *team.Name == slug && team.ID == nil {
				return nil, fmt.Errorf("team %s has no ID", slug)
			}
			teams = append(teams, team)
		}
		if int64(len(teams)) >= resp.Payload.TotalCount && len(resp.Payload.Teams) < int(limit) {
			return teams, nil
		}
		if len(resp.Payload.Teams) == 0 {
			return nil, fmt.Errorf("incomplete Grafana team search while deleting %s", slug)
		}
	}
}

func (r *grafanaReconciler) deletionFolder(ctx context.Context, slug string) (string, error) {
	limit := int64(1000)
	var matches []string
	stableUID := "nais-" + slug
	folder, err := r.folders.GetFolderByUIDWithParams(&grafanafolders.GetFolderByUIDParams{FolderUID: stableUID, Context: ctx})
	if err == nil {
		if folder == nil || folder.Payload == nil || folder.Payload.UID != stableUID {
			return "", fmt.Errorf("getting team folder %s for deletion: invalid response", stableUID)
		}
		return stableUID, nil
	}
	if !grafanaResourceNotFound(err) {
		return "", fmt.Errorf("getting team folder %s for deletion: %w", stableUID, err)
	}
	foundStable := false
	for page := int64(1); ; page++ {
		resp, err := r.folders.GetFolders(&grafanafolders.GetFoldersParams{Limit: &limit, Page: &page, Context: ctx})
		if err != nil {
			return "", fmt.Errorf("listing team folders for deletion: %w", err)
		}
		if resp == nil {
			return "", fmt.Errorf("listing team folders for deletion: empty response")
		}
		for _, folder := range resp.Payload {
			if folder == nil || folder.UID == "" {
				return "", fmt.Errorf("invalid folder while deleting team %s", slug)
			}
			if folder.UID == stableUID {
				foundStable = true
			}
			if folder.ParentUID == "" && folder.Title == slug {
				matches = append(matches, folder.UID)
			}
		}
		if len(resp.Payload) < int(limit) {
			break
		}
	}
	if foundStable {
		return stableUID, nil
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("multiple folders titled %q; cannot determine which to delete", slug)
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	return "", nil
}

func deletionContactPointOwned(name, slug string, teams []*models.TeamDTO) bool {
	if !strings.HasPrefix(name, "team-"+slug+"-") {
		return false
	}
	for _, team := range teams {
		if strings.HasPrefix(*team.Name, slug+"-") && strings.HasPrefix(name, "team-"+*team.Name+"-") {
			return false
		}
	}
	return true
}

func removeTeamNotificationRoutes(route *models.Route, slug string, removed map[string]bool) (*models.Route, error) {
	if route == nil {
		return nil, fmt.Errorf("nil notification route in policy tree")
	}
	matches, err := routeMatchesTeam(route, slug)
	if err != nil {
		return nil, err
	}
	if matches {
		return nil, fmt.Errorf("root notification route matches team %s; manual cleanup required", slug)
	}
	planned := *route
	if route.Routes != nil {
		planned.Routes = make([]*models.Route, 0, len(route.Routes))
	}
	for _, child := range route.Routes {
		if reconciledTeamNotificationRoute(child, slug) {
			if err := notificationRouteReceivers(child, removed); err != nil {
				return nil, err
			}
			continue
		}
		if err := checkNestedTeamRoutes([]*models.Route{child}, slug, nil); err != nil {
			return nil, fmt.Errorf("cannot delete notification policies for team %s; manual cleanup required: %w", slug, err)
		}
		planned.Routes = append(planned.Routes, child)
	}
	if len(route.Routes) > 0 && len(planned.Routes) == 0 {
		planned.Routes = nil
	}
	return &planned, nil
}

func reconciledTeamNotificationRoute(route *models.Route, slug string) bool {
	if route == nil {
		return false
	}
	if len(route.Routes) == 0 {
		for _, matcher := range route.ObjectMatchers {
			if len(matcher) == 3 && matcher[0] == "env" && matcher[1] == "=" && matcher[2] != "" {
				return sameNotificationRoute(route, buildEnvironmentNotificationRoute(slug, matcher[2]))
			}
		}
		return false
	}
	shell := *route
	shell.Routes = nil
	parent := &models.Route{ObjectMatchers: models.ObjectMatchers{{"team", "=", slug}}}
	if !sameNotificationRoute(&shell, parent) {
		return false
	}
	fallback := route.Routes[len(route.Routes)-1]
	if fallback == nil || !sameNotificationRoute(fallback, &models.Route{MuteTimeIntervals: []string{discardMuteTiming}}) {
		return false
	}
	seen := make(map[string]bool)
	for _, child := range route.Routes[:len(route.Routes)-1] {
		if child == nil || len(child.ObjectMatchers) != 1 {
			return false
		}
		matcher := child.ObjectMatchers[0]
		if len(matcher) != 3 || matcher[0] != "env" || matcher[1] != "=" || matcher[2] == "" || seen[matcher[2]] {
			return false
		}
		expected := buildEnvironmentNotificationRoute(slug, matcher[2])
		expected.ObjectMatchers = expected.ObjectMatchers[1:]
		if !sameNotificationRoute(child, expected) {
			return false
		}
		seen[matcher[2]] = true
	}
	return true
}

func notificationRouteReceivers(route *models.Route, receivers map[string]bool) error {
	if route == nil {
		return fmt.Errorf("nil notification route while collecting contact point references")
	}
	if route.Receiver != "" {
		receivers[route.Receiver] = true
	}
	for _, child := range route.Routes {
		if err := notificationRouteReceivers(child, receivers); err != nil {
			return err
		}
	}
	return nil
}
