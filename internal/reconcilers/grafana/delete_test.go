package grafana_reconciler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/go-openapi/strfmt"
	grafanaclient "github.com/grafana/grafana-openapi-client-go/client"
	grafanafolders "github.com/grafana/grafana-openapi-client-go/client/folders"
	grafanateams "github.com/grafana/grafana-openapi-client-go/client/teams"
	"github.com/grafana/grafana-openapi-client-go/models"
	"github.com/nais/api-reconcilers/internal/cmd/reconciler/config"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
)

type deletionGrafana struct {
	mu            sync.Mutex
	tree          *models.Route
	points        []*models.EmbeddedContactPoint
	folders       []*models.FolderSearchHit
	rules         models.ProvisionedAlertRules
	teams         []*models.TeamDTO
	mutations     []string
	failure       string
	failed        bool
	changeAtRead  int
	policyReads   int
	dashboards    int
	libraryPanels int
	disappear     bool
}

func newDeletionGrafana(t *testing.T) (*deletionGrafana, *grafanaReconciler) {
	t.Helper()
	log, _ := test.NewNullLogger()
	routes := (&grafanaReconciler{}).buildNotificationRoutes("idm", []*protoapi.TeamEnvironment{{
		EnvironmentName: "dev-gcp", SlackAlertsChannel: "#idm",
	}}, log)
	policies, err := planTeamNotificationRoutes(nil, routes, "idm")
	if err != nil {
		t.Fatal(err)
	}
	state := &deletionGrafana{
		tree: &models.Route{Receiver: "default", Provenance: models.Provenance("api"), Routes: []*models.Route{
			{Receiver: "other", Continue: true, ObjectMatchers: models.ObjectMatchers{{"team", "=", "other"}}},
			policies[0],
			{Receiver: "manual-idm", ObjectMatchers: models.ObjectMatchers{{"grafana_folder", "=", "idm"}}},
			{Receiver: "team-idm-shared", ObjectMatchers: models.ObjectMatchers{{"team", "=", "other"}}},
		}},
		points: []*models.EmbeddedContactPoint{
			{UID: "adopted-uid", Name: "team-idm-dev-gcp"},
			{UID: "old-environment", Name: "team-idm-removed-env"},
			{UID: "shared", Name: "team-idm-shared"},
			{UID: "direct", Name: "team-idm-direct"},
			{UID: "manual", Name: "manual-idm"},
			{UID: "hyphenated-team", Name: "team-idm-other-dev-gcp"},
			{UID: "other", Name: "other"},
		},
		folders: []*models.FolderSearchHit{
			{UID: "nais-idm", Title: "idm"},
			{UID: "subfolder", Title: "nested", ParentUID: "nais-idm"},
			{UID: "nais-other", Title: "other"},
		},
		rules: models.ProvisionedAlertRules{
			{UID: "own-rule", FolderUID: new("nais-idm")},
			{UID: "nested-rule", FolderUID: new("subfolder")},
			{UID: "other-rule", FolderUID: new("nais-other"), NotificationSettings: &models.AlertRuleNotificationSettings{Receiver: new("team-idm-direct")}},
		},
		teams: []*models.TeamDTO{
			{ID: new(int64(1)), Name: new("idm")},
			{ID: new(int64(2)), Name: new("idm-other")},
		},
		dashboards: 2, libraryPanels: 3,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		operation := request.Method + " " + request.URL.Path
		if operation == state.failure && !state.failed {
			state.failed = true
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte(`{"message":"temporary failure"}`)); err != nil {
				t.Error(err)
			}
			return
		}
		write := func(value any) {
			t.Helper()
			if err := json.NewEncoder(w).Encode(value); err != nil {
				t.Error(err)
			}
		}
		switch {
		case operation == "GET /api/teams/search":
			write(&models.SearchTeamQueryResult{Teams: state.teams, TotalCount: int64(len(state.teams))})
		case operation == "GET /api/folders":
			write(state.folders)
		case operation == "GET /api/folders/nais-idm":
			for _, folder := range state.folders {
				if folder.UID == "nais-idm" {
					write(&models.Folder{UID: folder.UID, Title: folder.Title, ParentUID: folder.ParentUID})
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			write(map[string]string{"message": "not found"})
		case operation == "GET /api/v1/provisioning/contact-points":
			write(state.points)
		case operation == "GET /api/v1/provisioning/alert-rules":
			write(state.rules)
		case operation == "GET /api/v1/provisioning/policies":
			state.policyReads++
			if state.policyReads == state.changeAtRead {
				state.tree.RepeatInterval = "12h"
			}
			write(state.tree)
		case operation == "PUT /api/v1/provisioning/policies":
			if request.Header.Get("X-Disable-Provenance") != "" {
				t.Error("policy cleanup must preserve provisioning")
			}
			var submitted models.Route
			if err := json.NewDecoder(request.Body).Decode(&submitted); err != nil {
				t.Error(err)
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			state.tree = &submitted
			state.mutations = append(state.mutations, operation)
			w.WriteHeader(http.StatusAccepted)
			write(map[string]string{"message": "updated"})
		case operation == "DELETE /api/folders/nais-idm" || operation == "DELETE /api/folders/legacy-uid":
			if request.URL.Query().Get("forceDeleteRules") != "true" {
				t.Error("folder deletion must include alert rules")
			}
			state.folders = []*models.FolderSearchHit{{UID: "nais-other", Title: "other"}}
			state.rules = state.rules[2:]
			state.dashboards, state.libraryPanels = 0, 0
			state.mutations = append(state.mutations, operation)
			if state.disappear {
				w.WriteHeader(http.StatusNotFound)
				write(map[string]string{"message": "already deleted"})
				return
			}
			write(map[string]string{"message": "deleted"})
		case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/api/v1/provisioning/contact-points/"):
			uid := strings.TrimPrefix(request.URL.Path, "/api/v1/provisioning/contact-points/")
			state.points = slices.DeleteFunc(state.points, func(point *models.EmbeddedContactPoint) bool { return point.UID == uid })
			state.mutations = append(state.mutations, operation)
			if state.disappear {
				w.WriteHeader(http.StatusNotFound)
				write(map[string]string{"message": "already deleted"})
				return
			}
			w.WriteHeader(http.StatusAccepted)
			write(map[string]string{"message": "deleted"})
		case operation == "DELETE /api/teams/1":
			state.teams = slices.DeleteFunc(state.teams, func(team *models.TeamDTO) bool { return *team.Name == "idm" })
			state.mutations = append(state.mutations, operation)
			if state.disappear {
				w.WriteHeader(http.StatusNotFound)
				write(map[string]string{"message": "already deleted"})
				return
			}
			write(map[string]string{"message": "deleted"})
		default:
			t.Errorf("unexpected request %s", operation)
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := grafanaclient.NewHTTPClientWithConfig(strfmt.Default, &grafanaclient.TransportConfig{
		Host: endpoint.Host, Schemes: []string{endpoint.Scheme}, BasePath: "/api",
	})
	reconciler := New(nil, client.Teams, client.Folders, nil, nil, nil, nil, client.Provisioning, config.FeatureFlags{}, "").(*grafanaReconciler)
	return state, reconciler
}

func TestDeleteGrafanaTeamResources(t *testing.T) {
	for _, mode := range []string{"normal", "flat policies", "already absent", "adopted folder", "renamed folder", "moved folder", "disappears during deletion"} {
		t.Run(mode, func(t *testing.T) {
			state, reconciler := newDeletionGrafana(t)
			state.mu.Lock()
			switch mode {
			case "flat policies":
				state.tree.Routes[1] = buildEnvironmentNotificationRoute("idm", "dev-gcp")
			case "already absent":
				state.teams = state.teams[1:]
			case "adopted folder":
				state.folders[0].UID = "legacy-uid"
			case "renamed folder":
				state.folders[0].Title = "renamed"
			case "moved folder":
				state.folders[0].ParentUID = "nais-other"
			case "disappears during deletion":
				state.disappear = true
			}
			before, err := json.Marshal([]*models.Route{state.tree.Routes[0], state.tree.Routes[2], state.tree.Routes[3]})
			state.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			log, hook := test.NewNullLogger()
			if err := reconciler.Delete(context.Background(), nil, &protoapi.Team{Slug: "idm"}, log); err != nil {
				t.Fatal(err)
			}
			state.mu.Lock()
			if state.dashboards != 0 || state.libraryPanels != 0 || len(state.folders) != 1 || len(state.rules) != 1 {
				t.Error("folder and all its contents must be deleted, preserving other folders")
			}
			after, err := json.Marshal(state.tree.Routes)
			if err != nil || string(before) != string(after) || state.tree.Provenance != "api" {
				t.Errorf("unrelated routes or provenance changed: %s, %v", after, err)
			}
			var remaining []string
			for _, point := range state.points {
				remaining = append(remaining, point.UID)
			}
			if !slices.Equal(remaining, []string{"shared", "direct", "manual", "hyphenated-team", "other"}) {
				t.Errorf("wrong contact points retained: %v", remaining)
			}
			if len(state.teams) != 1 || *state.teams[0].Name != "idm-other" {
				t.Error("only the deleted Grafana team should be removed")
			}
			if !strings.HasPrefix(state.mutations[0], "DELETE /api/folders/") ||
				state.mutations[1] != "PUT /api/v1/provisioning/policies" {
				t.Errorf("folder contents must be removed before policies: %v", state.mutations)
			}
			mutations := len(state.mutations)
			state.mu.Unlock()
			warnings := 0
			for _, entry := range hook.AllEntries() {
				if entry.Level == logrus.WarnLevel {
					warnings++
				}
			}
			if warnings < 2 {
				t.Fatal("shared contact points must be reported")
			}
			if err := reconciler.Delete(context.Background(), nil, &protoapi.Team{Slug: "idm"}, log); err != nil {
				t.Fatalf("repeated deletion failed: %v", err)
			}
			state.mu.Lock()
			defer state.mu.Unlock()
			if len(state.mutations) != mutations {
				t.Errorf("already completed cleanup should not mutate resources: %v", state.mutations)
			}
		})
	}
}

func TestDeleteGrafanaTeamRetry(t *testing.T) {
	for _, operation := range []string{
		"GET /api/folders/nais-idm",
		"GET /api/v1/provisioning/policies",
		"GET /api/v1/provisioning/contact-points",
		"GET /api/v1/provisioning/alert-rules",
		"DELETE /api/folders/nais-idm",
		"PUT /api/v1/provisioning/policies",
		"DELETE /api/v1/provisioning/contact-points/old-environment",
		"DELETE /api/teams/1",
	} {
		t.Run(operation, func(t *testing.T) {
			state, reconciler := newDeletionGrafana(t)
			state.mu.Lock()
			state.failure = operation
			state.mu.Unlock()
			log, _ := test.NewNullLogger()
			if err := reconciler.Delete(context.Background(), nil, &protoapi.Team{Slug: "idm"}, log); err == nil {
				t.Fatal("failed cleanup must return an error")
			}
			state.mu.Lock()
			if len(state.teams) != 2 {
				t.Error("team must be retained until cleanup succeeds")
			}
			state.mu.Unlock()
			if err := reconciler.Delete(context.Background(), nil, &protoapi.Team{Slug: "idm"}, log); err != nil {
				t.Fatalf("cleanup retry failed: %v", err)
			}
			state.mu.Lock()
			defer state.mu.Unlock()
			if len(state.teams) != 1 || len(state.folders) != 1 || len(state.points) != 5 {
				t.Fatal("retry did not finish cleanup")
			}
		})
	}
}

func TestDeleteLastPolicyAndMultipleContactPointIntegrations(t *testing.T) {
	state, reconciler := newDeletionGrafana(t)
	state.mu.Lock()
	state.tree = &models.Route{Receiver: "default", Routes: []*models.Route{state.tree.Routes[1]}}
	state.points = []*models.EmbeddedContactPoint{
		{UID: "first", Name: "team-idm-dev-gcp"},
		{UID: "second", Name: "team-idm-dev-gcp"},
	}
	state.rules = state.rules[:2]
	state.mu.Unlock()
	log, _ := test.NewNullLogger()
	for range 2 {
		if err := reconciler.Delete(context.Background(), nil, &protoapi.Team{Slug: "idm"}, log); err != nil {
			t.Fatal(err)
		}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.tree.Routes != nil || len(state.points) != 0 || state.tree.Provenance != "api" {
		t.Fatal("last team policy and all contact point integrations must be removed idempotently")
	}
}

func TestDeleteGrafanaTeamDetectsExternalChanges(t *testing.T) {
	for _, read := range []int{2, 3} {
		t.Run(string(rune('0'+read)), func(t *testing.T) {
			state, reconciler := newDeletionGrafana(t)
			state.mu.Lock()
			state.changeAtRead = read
			state.mu.Unlock()
			log, _ := test.NewNullLogger()
			err := reconciler.Delete(context.Background(), nil, &protoapi.Team{Slug: "idm"}, log)
			if err == nil || !strings.Contains(err.Error(), "changed") {
				t.Fatalf("expected a concurrent modification error, got %v", err)
			}
			state.mu.Lock()
			defer state.mu.Unlock()
			if state.tree.RepeatInterval != "12h" || len(state.points) != 7 || len(state.teams) != 2 {
				t.Fatal("external changes must be preserved and contact point/team deletion blocked")
			}
		})
	}
}

func TestRemoveTeamNotificationRoutes(t *testing.T) {
	for _, mode := range []string{"multiple environments", "flat policies", "flat reversed matchers", "mixed layouts", "fallback only", "no team policy"} {
		t.Run(mode, func(t *testing.T) {
			log, _ := test.NewNullLogger()
			environments := []*protoapi.TeamEnvironment{
				{EnvironmentName: "dev-gcp", SlackAlertsChannel: "#idm"},
				{EnvironmentName: "removed-environment", SlackAlertsChannel: "#idm-old"},
			}
			if mode == "fallback only" {
				environments = nil
			}
			flat := (&grafanaReconciler{}).buildNotificationRoutes("idm", environments, log)
			generated, err := planTeamNotificationRoutes(nil, flat, "idm")
			if err != nil {
				t.Fatal(err)
			}
			unrelated := []*models.Route{
				{Receiver: "before", Continue: true, ObjectMatchers: models.ObjectMatchers{{"team", "=", "other"}}},
				{Receiver: "folder", ObjectMatchers: models.ObjectMatchers{{"grafana_folder", "=", "idm"}}},
				{Receiver: "namespace", Match: map[string]string{"namespace": "idm"}},
				{Receiver: "another team", ObjectMatchers: models.ObjectMatchers{{"team", "=", "other"}, {"namespace", "=", "idm"}}},
				{Receiver: "another team folder", ObjectMatchers: models.ObjectMatchers{{"team", "=", "other"}, {"grafana_folder", "=", "idm"}}},
				{Receiver: "parsed namespace", Matchers: models.Matchers{{Name: "namespace", Type: matchEqual, Value: "idm"}}},
				{Receiver: "nested", Routes: []*models.Route{{Receiver: "nested folder", Match: map[string]string{"grafana_folder": "idm"}}}},
			}
			root := &models.Route{Receiver: "default", RepeatInterval: "12h", Routes: slices.Clone(unrelated)}
			switch mode {
			case "flat policies", "flat reversed matchers":
				if mode == "flat reversed matchers" {
					for _, route := range flat {
						slices.Reverse(route.ObjectMatchers)
					}
				}
				root.Routes = slices.Insert(root.Routes, 1, flat...)
			case "mixed layouts":
				root.Routes = slices.Insert(root.Routes, 1, generated[0], flat[0])
			case "no team policy":
			default:
				root.Routes = slices.Insert(root.Routes, 1, generated[0])
			}
			before, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			receivers := make(map[string]bool)
			planned, err := removeTeamNotificationRoutes(root, "idm", receivers)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(planned.Routes, unrelated) || planned.Receiver != root.Receiver || planned.RepeatInterval != "12h" {
				t.Fatalf("unrelated policies or root settings changed: %+v", planned)
			}
			for _, route := range flat {
				if receivers[route.Receiver] != (mode != "no team policy") {
					t.Fatalf("wrong removed receivers: %v", receivers)
				}
			}
			expectedReceivers := len(flat)
			if mode == "no team policy" {
				expectedReceivers = 0
			}
			if len(receivers) != expectedReceivers {
				t.Fatalf("unrelated receivers collected for deletion: %v", receivers)
			}
			after, err := json.Marshal(root)
			if err != nil || string(before) != string(after) {
				t.Fatal("planning mutated the original policy tree")
			}
		})
	}
}

func TestDeleteGrafanaTeamRejectsModifiedPolicies(t *testing.T) {
	for _, target := range []string{"parent", "environment", "fallback", "flat"} {
		for _, change := range []struct {
			name   string
			modify func(*models.Route)
		}{
			{"receiver", func(route *models.Route) { route.Receiver = "manual" }},
			{"continue", func(route *models.Route) { route.Continue = true }},
			{"group by", func(route *models.Route) { route.GroupBy = []string{"custom"} }},
			{"group wait", func(route *models.Route) { route.GroupWait = "1m" }},
			{"group interval", func(route *models.Route) { route.GroupInterval = "10m" }},
			{"repeat interval", func(route *models.Route) { route.RepeatInterval = "12h" }},
			{"mute timing", func(route *models.Route) { route.MuteTimeIntervals = []string{"custom"} }},
			{"active timing", func(route *models.Route) { route.ActiveTimeIntervals = []string{"custom"} }},
			{"extra matcher", func(route *models.Route) {
				route.ObjectMatchers = append(route.ObjectMatchers, models.ObjectMatcher{"severity", "=", "critical"})
			}},
			{"legacy matcher", func(route *models.Route) { route.Match = map[string]string{"severity": "critical"} }},
			{"regex matcher", func(route *models.Route) { route.MatchRe = map[string]string{"severity": ".*"} }},
			{"parsed matcher", func(route *models.Route) {
				route.Matchers = models.Matchers{{Name: "severity", Type: matchEqual, Value: "critical"}}
			}},
			{"nested manual route", func(route *models.Route) {
				route.Routes = append(route.Routes, &models.Route{Receiver: "manual"})
			}},
		} {
			t.Run(target+"/"+change.name, func(t *testing.T) {
				state, reconciler := newDeletionGrafana(t)
				route := state.tree.Routes[1]
				switch target {
				case "flat":
					route = buildEnvironmentNotificationRoute("idm", "dev-gcp")
					state.tree.Routes[1] = route
				case "environment":
					route = route.Routes[0]
				case "fallback":
					route = route.Routes[1]
				}
				change.modify(route)
				before, err := json.Marshal(state.tree)
				if err != nil {
					t.Fatal(err)
				}
				log, _ := test.NewNullLogger()
				err = reconciler.Delete(context.Background(), nil, &protoapi.Team{Slug: "idm"}, log)
				if err == nil || !strings.Contains(err.Error(), "manual cleanup required") {
					t.Fatalf("expected a manual cleanup error, got %v", err)
				}
				state.mu.Lock()
				defer state.mu.Unlock()
				after, err := json.Marshal(state.tree)
				if err != nil || string(before) != string(after) || len(state.mutations) != 0 {
					t.Fatalf("modified policy must block all mutations: %v", state.mutations)
				}
			})
		}
	}
}

func TestDeleteGrafanaTeamRejectsUnmanagedPolicyLayouts(t *testing.T) {
	for _, change := range []struct {
		name   string
		modify func(*models.Route)
	}{
		{"missing fallback", func(tree *models.Route) { tree.Routes[1].Routes = tree.Routes[1].Routes[:1] }},
		{"missing children", func(tree *models.Route) { tree.Routes[1].Routes = nil }},
		{"nil policy", func(tree *models.Route) { tree.Routes = append(tree.Routes, nil) }},
		{"nil child", func(tree *models.Route) { tree.Routes[1].Routes[0] = nil }},
		{"nil fallback", func(tree *models.Route) { tree.Routes[1].Routes[1] = nil }},
		{"duplicate environment", func(tree *models.Route) {
			parent := tree.Routes[1]
			parent.Routes = slices.Insert(parent.Routes, 1, parent.Routes[0])
		}},
		{"fallback before environment", func(tree *models.Route) { slices.Reverse(tree.Routes[1].Routes) }},
		{"empty environment", func(tree *models.Route) {
			child := tree.Routes[1].Routes[0]
			child.ObjectMatchers = models.ObjectMatchers{{"env", "=", ""}}
			child.Receiver = "team-idm-"
		}},
		{"malformed environment matcher", func(tree *models.Route) {
			tree.Routes[1].Routes[0].ObjectMatchers = models.ObjectMatchers{{"env"}}
		}},
		{"environment regex", func(tree *models.Route) { tree.Routes[1].Routes[0].ObjectMatchers[0][1] = "=~" }},
		{"environment routed to another team", func(tree *models.Route) { tree.Routes[1].Routes[0].Receiver = "team-other-dev-gcp" }},
		{"nested generated parent", func(tree *models.Route) {
			tree.Routes[1] = &models.Route{Receiver: "manual", Routes: []*models.Route{tree.Routes[1]}}
		}},
		{"manual team route", func(tree *models.Route) {
			tree.Routes = append(tree.Routes, &models.Route{Receiver: "manual", ObjectMatchers: models.ObjectMatchers{{"team", "=", "idm"}}})
		}},
		{"nested flat policy", func(tree *models.Route) {
			tree.Routes[1] = &models.Route{Receiver: "manual", Routes: []*models.Route{buildEnvironmentNotificationRoute("idm", "dev-gcp")}}
		}},
		{"flat policy with empty environment", func(tree *models.Route) {
			tree.Routes[1] = buildEnvironmentNotificationRoute("idm", "")
		}},
		{"flat policy with environment regex", func(tree *models.Route) {
			tree.Routes[1] = buildEnvironmentNotificationRoute("idm", "dev-gcp")
			tree.Routes[1].ObjectMatchers[1][1] = "=~"
		}},
		{"flat policy with malformed matcher", func(tree *models.Route) {
			tree.Routes[1] = buildEnvironmentNotificationRoute("idm", "dev-gcp")
			tree.Routes[1].ObjectMatchers[1] = models.ObjectMatcher{"env"}
		}},
		{"flat policy with team regex", func(tree *models.Route) {
			tree.Routes[1] = buildEnvironmentNotificationRoute("idm", "dev-gcp")
			tree.Routes[1].ObjectMatchers[0][1] = "=~"
		}},
		{"flat policy with duplicate team matcher", func(tree *models.Route) {
			tree.Routes[1] = buildEnvironmentNotificationRoute("idm", "dev-gcp")
			tree.Routes[1].ObjectMatchers[1] = models.ObjectMatcher{"team", "=", "idm"}
		}},
		{"flat policy routed to another team", func(tree *models.Route) {
			tree.Routes[1] = buildEnvironmentNotificationRoute("idm", "dev-gcp")
			tree.Routes[1].Receiver = "team-other-dev-gcp"
		}},
		{"legacy team matcher", func(tree *models.Route) {
			tree.Routes[1].ObjectMatchers = nil
			tree.Routes[1].Match = map[string]string{"team": "idm"}
		}},
		{"root matches team", func(tree *models.Route) { tree.ObjectMatchers = models.ObjectMatchers{{"team", "=", "idm"}} }},
		{"broad team regex", func(tree *models.Route) {
			tree.Routes[1].ObjectMatchers = models.ObjectMatchers{{"team", "=~", "idm|other"}}
		}},
		{"negative team matcher", func(tree *models.Route) {
			tree.Routes[1].ObjectMatchers = models.ObjectMatchers{{"team", "!=", "other"}}
		}},
		{"invalid team regex", func(tree *models.Route) { tree.Routes[1].ObjectMatchers = models.ObjectMatchers{{"team", "=~", "["}} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			state, reconciler := newDeletionGrafana(t)
			change.modify(state.tree)
			log, _ := test.NewNullLogger()
			if err := reconciler.Delete(context.Background(), nil, &protoapi.Team{Slug: "idm"}, log); err == nil {
				t.Fatal("unmanaged policy must block cleanup")
			}
			state.mu.Lock()
			defer state.mu.Unlock()
			if len(state.mutations) != 0 {
				t.Fatalf("policy preflight failure must not mutate any resources: %v", state.mutations)
			}
		})
	}
}

func TestDeletionFolderPaginationAndAmbiguity(t *testing.T) {
	for _, mode := range []string{"later page", "duplicate titles"} {
		t.Run(mode, func(t *testing.T) {
			folders := NewMockFoldersClientService(t)
			folders.EXPECT().GetFolderByUIDWithParams(mock.Anything).Return(nil, grafanafolders.NewGetFolderByUIDNotFound()).Once()
			reconciler := &grafanaReconciler{folders: folders}
			if mode == "later page" {
				hits := make([]*models.FolderSearchHit, 1000)
				for i := range hits {
					hits[i] = &models.FolderSearchHit{UID: "unrelated", Title: "other"}
				}
				folders.EXPECT().GetFolders(mock.MatchedBy(func(params *grafanafolders.GetFoldersParams) bool { return *params.Page == 1 })).
					Return(&grafanafolders.GetFoldersOK{Payload: hits}, nil).Once()
				folders.EXPECT().GetFolders(mock.MatchedBy(func(params *grafanafolders.GetFoldersParams) bool { return *params.Page == 2 })).
					Return(&grafanafolders.GetFoldersOK{Payload: []*models.FolderSearchHit{{UID: "nais-idm", Title: "renamed"}}}, nil).Once()
				uid, err := reconciler.deletionFolder(context.Background(), "idm")
				if err != nil || uid != "nais-idm" {
					t.Fatalf("did not find renamed managed folder on second page: %q, %v", uid, err)
				}
			} else {
				folders.EXPECT().GetFolders(mock.Anything).Return(&grafanafolders.GetFoldersOK{Payload: []*models.FolderSearchHit{
					{UID: "first", Title: "idm"}, {UID: "second", Title: "idm"},
				}}, nil).Once()
				if _, err := reconciler.deletionFolder(context.Background(), "idm"); err == nil {
					t.Fatal("ambiguous legacy folder must not be deleted")
				}
			}
		})
	}
}

func TestDeletionTeamsPagination(t *testing.T) {
	teams := NewMockTeamsClientService(t)
	teams.EXPECT().SearchTeams(mock.MatchedBy(func(params *grafanateams.SearchTeamsParams) bool { return *params.Page == 1 })).
		Return(&grafanateams.SearchTeamsOK{Payload: &models.SearchTeamQueryResult{Teams: []*models.TeamDTO{{Name: new("idm"), ID: new(int64(1))}}, TotalCount: 2}}, nil).Once()
	teams.EXPECT().SearchTeams(mock.MatchedBy(func(params *grafanateams.SearchTeamsParams) bool { return *params.Page == 2 })).
		Return(&grafanateams.SearchTeamsOK{Payload: &models.SearchTeamQueryResult{Teams: []*models.TeamDTO{{Name: new("idm-other")}}, TotalCount: 2}}, nil).Once()
	reconciler := &grafanaReconciler{teams: teams}
	found, err := reconciler.deletionTeams(context.Background(), "idm")
	if err != nil || len(found) != 2 || deletionContactPointOwned("team-idm-other-dev-gcp", "idm", found) ||
		!deletionContactPointOwned("team-idm-dev-gcp", "idm", found) {
		t.Fatalf("team ownership must account for paginated prefix collisions: %v, %v", found, err)
	}
}

func TestDeleteGrafanaTeamPreflightFailure(t *testing.T) {
	for _, mode := range []string{"ambiguous route", "canceled", "empty slug"} {
		t.Run(mode, func(t *testing.T) {
			state, reconciler := newDeletionGrafana(t)
			ctx := context.Background()
			slug := "idm"
			switch mode {
			case "ambiguous route":
				state.mu.Lock()
				state.tree.Routes = append(state.tree.Routes, &models.Route{ObjectMatchers: models.ObjectMatchers{{"team", "=~", "idm|other"}}})
				state.mu.Unlock()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "empty slug":
				slug = ""
			}
			log, _ := test.NewNullLogger()
			if err := reconciler.Delete(ctx, nil, &protoapi.Team{Slug: slug}, log); err == nil {
				t.Fatal("unsafe cleanup must fail")
			}
			state.mu.Lock()
			defer state.mu.Unlock()
			if !reflect.DeepEqual(state.mutations, []string(nil)) {
				t.Fatalf("preflight failure must not delete resources: %v", state.mutations)
			}
		})
	}
}
