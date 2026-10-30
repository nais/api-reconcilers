package grafana_reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-openapi/strfmt"
	grafanaclient "github.com/grafana/grafana-openapi-client-go/client"
	grafanaprovisioning "github.com/grafana/grafana-openapi-client-go/client/provisioning"
	grafanateams "github.com/grafana/grafana-openapi-client-go/client/teams"
	"github.com/grafana/grafana-openapi-client-go/models"
	"github.com/nais/api-reconcilers/internal/cmd/reconciler/config"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
)

func TestNotificationRoutesToAdd(t *testing.T) {
	log, _ := test.NewNullLogger()
	reconciler := &grafanaReconciler{}
	desired := reconciler.buildNotificationRoutes("idm", []*protoapi.TeamEnvironment{
		{EnvironmentName: "dev-gcp", SlackAlertsChannel: "#team-idm"},
		{EnvironmentName: "prod-gcp", SlackAlertsChannel: "#team-idm"},
	}, log)
	manual := &models.Route{
		Receiver:       "team-idm-alerts-test",
		ObjectMatchers: models.ObjectMatchers{{"team", "=", "idm"}, {"env", "=~", "dev.*"}},
		Routes: []*models.Route{{
			Receiver:          "team-idm-alerts-test",
			ObjectMatchers:    models.ObjectMatchers{{"type", "=", "batch"}},
			MuteTimeIntervals: []string{"Kveld+natt"},
		}},
	}
	other := &models.Route{Receiver: "team-tsm", ObjectMatchers: models.ObjectMatchers{{"team", "=", "tsm"}}}

	t.Run("preserves unrelated routes and adds only missing routes", func(t *testing.T) {
		existing := []*models.Route{other, desired[0]}
		additions, err := routesToAdd(existing, desired, "idm")
		if err != nil || len(additions) != 1 || additions[0] != desired[1] {
			t.Fatalf("additions = %v, err = %v", additions, err)
		}
		if len(existing) != 2 || existing[0] != other || existing[1] != desired[0] {
			t.Fatal("existing routes were modified")
		}
	})

	t.Run("exact existing routes need no write", func(t *testing.T) {
		additions, err := routesToAdd(desired, desired, "idm")
		if err != nil || len(additions) != 0 {
			t.Fatalf("additions = %v, err = %v", additions, err)
		}
	})

	tests := []struct {
		name     string
		existing []*models.Route
		desired  []*models.Route
	}{
		{"manual team route with children", []*models.Route{other, manual}, desired},
		{"unconfigured team environment", []*models.Route{desired[0]}, desired[1:]},
		{"changed route settings", []*models.Route{{
			Receiver:       desired[0].Receiver,
			ObjectMatchers: desired[0].ObjectMatchers,
			GroupWait:      "1m",
		}}, desired},
		{"receiver reused by another route", []*models.Route{{
			Receiver:       desired[0].Receiver,
			ObjectMatchers: models.ObjectMatchers{{"team", "=", "other"}},
		}}, desired},
		{"duplicate route", []*models.Route{desired[0], desired[0]}, desired},
		{"nested route for team", []*models.Route{{Routes: []*models.Route{manual}}}, desired},
		{"nested route reuses contact point", []*models.Route{{Routes: []*models.Route{{
			Receiver: desired[0].Receiver,
		}}}}, desired},
		{"regex team route", []*models.Route{{
			Receiver:       "custom",
			ObjectMatchers: models.ObjectMatchers{{"team", "=~", "id.*"}},
		}}, desired},
		{"legacy match route", []*models.Route{{Match: map[string]string{"team": "idm"}}}, desired},
		{"nil route", []*models.Route{nil}, desired},
		{"duplicate desired environments", nil, []*models.Route{desired[0], desired[0]}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := routesToAdd(tt.existing, tt.desired, "idm"); err == nil {
				t.Fatal("expected a conflict")
			}
		})
	}
	if len(manual.Routes) != 1 || len(manual.Routes[0].MuteTimeIntervals) != 1 {
		t.Fatal("manual route was modified")
	}
}

func TestTeamRegexMatching(t *testing.T) {
	matcher := func(pattern string, isEqual bool) *models.Matcher {
		name, isRegex := "team", true
		return &models.Matcher{Name: &name, Value: &pattern, IsRegex: &isRegex, IsEqual: isEqual}
	}

	tests := []struct {
		name     string
		route    *models.Route
		teamSlug string
		want     bool
	}{
		{"legacy substring", &models.Route{MatchRe: map[string]string{"team": "idm"}}, "idm-dev", false},
		{"legacy full match", &models.Route{MatchRe: map[string]string{"team": "idm-dev"}}, "idm-dev", true},
		{"legacy alternation anchored as a group", &models.Route{MatchRe: map[string]string{"team": "idm|idm-dev"}}, "idm-dev-extra", false},
		{"object substring", &models.Route{ObjectMatchers: models.ObjectMatchers{{"team", "=~", "idm"}}}, "idm-dev", false},
		{"object negated substring", &models.Route{ObjectMatchers: models.ObjectMatchers{{"team", "!~", "idm"}}}, "idm-dev", true},
		{"object negated full match", &models.Route{ObjectMatchers: models.ObjectMatchers{{"team", "!~", "idm-dev"}}}, "idm-dev", false},
		{"matcher substring", &models.Route{Matchers: models.Matchers{matcher("idm", true)}}, "idm-dev", false},
		{"matcher negated substring", &models.Route{Matchers: models.Matchers{matcher("idm", false)}}, "idm-dev", true},
		{"matcher negated full match", &models.Route{Matchers: models.Matchers{matcher("idm-dev", false)}}, "idm-dev", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := routeMatchesTeam(tt.route, tt.teamSlug)
			if err != nil || got != tt.want {
				t.Fatalf("routeMatchesTeam() = %v, %v; want %v", got, err, tt.want)
			}
		})
	}

	for _, route := range []*models.Route{
		{MatchRe: map[string]string{"team": "["}},
		{ObjectMatchers: models.ObjectMatchers{{"team", "=~", "["}}},
		{Matchers: models.Matchers{matcher("[", true)}},
	} {
		if _, err := routeMatchesTeam(route, "idm"); err == nil {
			t.Fatal("expected invalid team regex to fail")
		}
	}
}

func TestAllTeamMatchersMustMatch(t *testing.T) {
	matcher := func(value string, isRegex, isEqual bool) *models.Matcher {
		name := "team"
		return &models.Matcher{Name: &name, Value: &value, IsRegex: &isRegex, IsEqual: isEqual}
	}

	tests := []struct {
		name  string
		route *models.Route
		team  string
		want  bool
	}{
		{"matching object predicates", &models.Route{
			ObjectMatchers: models.ObjectMatchers{{"team", "=~", "aura|nais"}, {"team", "!=", "nais"}},
		}, "aura", true},
		{"object exclusion after matching regex", &models.Route{
			ObjectMatchers: models.ObjectMatchers{{"team", "=~", "aura|nais"}, {"team", "!=", "nais"}},
		}, "nais", false},
		{"object exclusion before matching regex", &models.Route{
			ObjectMatchers: models.ObjectMatchers{{"team", "!=", "nais"}, {"team", "=~", "aura|nais"}},
		}, "nais", false},
		{"matching structured predicates", &models.Route{
			Matchers: models.Matchers{matcher("aura|nais", true, true), matcher("nais", false, false)},
		}, "aura", true},
		{"structured exclusion", &models.Route{
			Matchers: models.Matchers{matcher("aura|nais", true, true), matcher("nais", false, false)},
		}, "nais", false},
		{"legacy match and regex agree", &models.Route{
			Match: map[string]string{"team": "nais"}, MatchRe: map[string]string{"team": "aura|nais"},
		}, "nais", true},
		{"legacy match excludes despite matching regex", &models.Route{
			Match: map[string]string{"team": "aura"}, MatchRe: map[string]string{"team": "aura|nais"},
		}, "nais", false},
		{"mixed formats exclude", &models.Route{
			Match: map[string]string{"team": "nais"}, ObjectMatchers: models.ObjectMatchers{{"team", "!=", "nais"}},
		}, "nais", false},
		{"other labels remain conservative", &models.Route{
			ObjectMatchers: models.ObjectMatchers{{"team", "=", "nais"}, {"env", "=", "dev-gcp"}},
		}, "nais", true},
		{"no team matcher", &models.Route{
			ObjectMatchers: models.ObjectMatchers{{"env", "=", "dev-gcp"}},
		}, "nais", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := routeMatchesTeam(tt.route, tt.team)
			if err != nil || got != tt.want {
				t.Fatalf("routeMatchesTeam() = %v, %v; want %v", got, err, tt.want)
			}
		})
	}

	route := &models.Route{
		ObjectMatchers: models.ObjectMatchers{{"team", "!=", "nais"}, {"team", "=~", "["}},
	}
	if _, err := routeMatchesTeam(route, "nais"); err == nil {
		t.Fatal("invalid matcher must fail even when another matcher excludes the team")
	}
}

func TestNotificationRoutesToAddWithRegex(t *testing.T) {
	log, _ := test.NewNullLogger()
	desired := (&grafanaReconciler{}).buildNotificationRoutes("idm-dev", []*protoapi.TeamEnvironment{{
		EnvironmentName: "prod-gcp", SlackAlertsChannel: "#idm",
	}}, log)

	additions, err := routesToAdd([]*models.Route{{
		Receiver: "manual", ObjectMatchers: models.ObjectMatchers{{"team", "=~", "idm"}},
	}}, desired, "idm-dev")
	if err != nil || len(additions) != 1 || additions[0] != desired[0] {
		t.Fatalf("substring regex should not conflict: additions = %v, err = %v", additions, err)
	}

	if _, err := routesToAdd([]*models.Route{{
		Receiver: "manual", ObjectMatchers: models.ObjectMatchers{{"team", "!~", "idm"}},
	}}, desired, "idm-dev"); err == nil {
		t.Fatal("negated substring regex should conflict")
	}
}

func TestNotificationRoutesWithExcludedTeam(t *testing.T) {
	log, _ := test.NewNullLogger()
	manual := &models.Route{
		Receiver: "manual",
		ObjectMatchers: models.ObjectMatchers{
			{"team", "=~", "aura|nais"},
			{"team", "!=", "nais"},
		},
	}
	desired := (&grafanaReconciler{}).buildNotificationRoutes("nais", []*protoapi.TeamEnvironment{{
		EnvironmentName: "prod-gcp", SlackAlertsChannel: "#nais",
	}}, log)

	additions, err := routesToAdd([]*models.Route{manual}, desired, "nais")
	if err != nil || len(additions) != 1 || additions[0] != desired[0] {
		t.Fatalf("excluded team should not conflict: additions = %v, err = %v", additions, err)
	}
	auraRoutes := (&grafanaReconciler{}).buildNotificationRoutes("aura", []*protoapi.TeamEnvironment{{
		EnvironmentName: "prod-gcp", SlackAlertsChannel: "#aura",
	}}, log)
	if _, err := routesToAdd([]*models.Route{manual}, auraRoutes, "aura"); err == nil {
		t.Fatal("applicable manual route should conflict")
	}

	for _, tt := range []struct {
		team    string
		blocked bool
	}{
		{"nais", false},
		{"aura", true},
	} {
		t.Run(tt.team, func(t *testing.T) {
			provisioning := NewMockProvisioningClientService(t)
			provisioning.EXPECT().GetPolicyTree().Return(&grafanaprovisioning.GetPolicyTreeOK{
				Payload: &models.Route{Routes: []*models.Route{manual}},
			}, nil).Once()
			reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning,
				config.FeatureFlags{EnableGrafanaAlerts: true}, "webhook").(*grafanaReconciler)
			err := reconciler.ensureNoNotificationRoutes(tt.team)
			if (err != nil) != tt.blocked {
				t.Fatalf("ensureNoNotificationRoutes() error = %v, want blocked = %v", err, tt.blocked)
			}
		})
	}
}

func TestNotificationPolicyWrites(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	environments := []*protoapi.TeamEnvironment{{EnvironmentName: "dev-gcp", SlackAlertsChannel: "#team-idm"}}

	t.Run("rejects manual routes before changing templates or contact points", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		manual := &models.Route{
			Receiver:       "team-idm-alerts-test",
			ObjectMatchers: models.ObjectMatchers{{"team", "=", "idm"}},
			Routes:         []*models.Route{{Receiver: "custom"}},
		}
		provisioning.EXPECT().GetPolicyTree().
			Return(&grafanaprovisioning.GetPolicyTreeOK{Payload: &models.Route{Routes: []*models.Route{manual}}}, nil).Once()

		reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
		err := reconciler.reconcileAlerting(ctx, "idm", environments, log)
		if err == nil || !strings.Contains(err.Error(), "manual migration") {
			t.Fatalf("expected a manual migration error, got %v", err)
		}
	})

	t.Run("appends only the new route and preserves existing children", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		existing := &models.Route{
			Receiver:       "tsm",
			ObjectMatchers: models.ObjectMatchers{{"team", "=", "tsm"}},
			Routes:         []*models.Route{{Receiver: "tsm-panic", MuteTimeIntervals: []string{"night"}}},
		}
		tree := &models.Route{Receiver: "default", Routes: []*models.Route{existing}}
		provisioning.EXPECT().GetPolicyTree().
			Return(&grafanaprovisioning.GetPolicyTreeOK{Payload: tree}, nil).Once()
		provisioning.EXPECT().PutPolicyTree(mock.MatchedBy(func(params *grafanaprovisioning.PutPolicyTreeParams) bool {
			return params.XDisableProvenance != nil && *params.XDisableProvenance == "true" &&
				params.Body == tree && len(tree.Routes) == 2 && tree.Routes[0] == existing &&
				tree.Routes[1].Receiver == "team-idm-dev-gcp" &&
				len(existing.Routes) == 1 && len(existing.Routes[0].MuteTimeIntervals) == 1
		})).Return(&grafanaprovisioning.PutPolicyTreeAccepted{}, nil).Once()

		reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
		if err := reconciler.updateNotificationPolicy(ctx, "idm", environments, tree, log); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("does not rewrite an unchanged tree", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
		route := reconciler.buildNotificationRoutes("idm", environments, log)[0]
		tree := &models.Route{Routes: []*models.Route{route}}
		provisioning.EXPECT().GetPolicyTree().
			Return(&grafanaprovisioning.GetPolicyTreeOK{Payload: tree}, nil).Once()
		if err := reconciler.updateNotificationPolicy(ctx, "idm", environments, tree, log); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("rejects a matching root route", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		provisioning.EXPECT().GetPolicyTree().Return(&grafanaprovisioning.GetPolicyTreeOK{
			Payload: &models.Route{ObjectMatchers: models.ObjectMatchers{{"team", "=", "idm"}}},
		}, nil).Once()
		reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
		if err := reconciler.updateNotificationPolicy(ctx, "idm", environments, &models.Route{}, log); err == nil || !strings.Contains(err.Error(), "root notification route") {
			t.Fatalf("expected a root route conflict, got %v", err)
		}
	})

	t.Run("rejects external changes to an unrelated route before PUT", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		baseline := &models.Route{Receiver: "default", Routes: []*models.Route{{
			Receiver: "team-tsm", ObjectMatchers: models.ObjectMatchers{{"team", "=", "tsm"}},
		}}}
		changed := &models.Route{Receiver: "default", Routes: []*models.Route{{
			Receiver: "team-tsm", ObjectMatchers: models.ObjectMatchers{{"team", "=", "tsm"}},
			MuteTimeIntervals: []string{"night"},
		}}}
		provisioning.EXPECT().GetPolicyTree().Return(&grafanaprovisioning.GetPolicyTreeOK{Payload: baseline}, nil).Once()
		provisioning.EXPECT().GetPolicyTree().Return(&grafanaprovisioning.GetPolicyTreeOK{Payload: changed}, nil).Once()
		provisioning.EXPECT().GetContactpoints(mock.Anything).Return(nil, nil).Once()
		provisioning.EXPECT().PostContactpoints(mock.Anything).Return(&grafanaprovisioning.PostContactpointsAccepted{}, nil).Once()
		reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
		reconciler.templatesInitialized = true
		err := reconciler.reconcileAlerting(ctx, "idm", environments, log)
		if err == nil || !strings.Contains(err.Error(), "refusing to overwrite external changes") {
			t.Fatalf("expected a stale policy tree error, got %v", err)
		}
	})
}

func TestNotificationPolicySerializesTeams(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	provisioning := NewMockProvisioningClientService(t)
	var stateMu sync.Mutex
	tree := &models.Route{Receiver: "default"}
	reads := 0
	firstRead := make(chan struct{})
	releaseFirstRead := make(chan struct{})

	provisioning.EXPECT().GetPolicyTree().RunAndReturn(func(...grafanaprovisioning.ClientOption) (*grafanaprovisioning.GetPolicyTreeOK, error) {
		stateMu.Lock()
		reads++
		readNumber := reads
		snapshot := &models.Route{Receiver: tree.Receiver, Routes: append([]*models.Route(nil), tree.Routes...)}
		stateMu.Unlock()
		if readNumber == 1 {
			close(firstRead)
			<-releaseFirstRead
		}
		return &grafanaprovisioning.GetPolicyTreeOK{Payload: snapshot}, nil
	}).Times(4)
	provisioning.EXPECT().GetContactpoints(mock.Anything).Return(nil, nil).Twice()
	provisioning.EXPECT().PostContactpoints(mock.Anything).Return(&grafanaprovisioning.PostContactpointsAccepted{}, nil).Twice()
	provisioning.EXPECT().PutPolicyTree(mock.Anything).RunAndReturn(func(params *grafanaprovisioning.PutPolicyTreeParams, _ ...grafanaprovisioning.ClientOption) (*grafanaprovisioning.PutPolicyTreeAccepted, error) {
		stateMu.Lock()
		tree = params.Body
		stateMu.Unlock()
		return &grafanaprovisioning.PutPolicyTreeAccepted{}, nil
	}).Twice()

	reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
	reconciler.templatesInitialized = true
	results := make(chan error, 2)
	go func() {
		results <- reconciler.reconcileAlerting(ctx, "idm", []*protoapi.TeamEnvironment{{
			EnvironmentName: "dev-gcp", SlackAlertsChannel: "#idm",
		}}, log)
	}()
	<-firstRead
	go func() {
		results <- reconciler.reconcileAlerting(ctx, "tsm", []*protoapi.TeamEnvironment{{
			EnvironmentName: "dev-gcp", SlackAlertsChannel: "#tsm",
		}}, log)
	}()
	close(releaseFirstRead)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	stateMu.Lock()
	defer stateMu.Unlock()
	if len(tree.Routes) != 2 || !reflect.DeepEqual(
		[]string{tree.Routes[0].Receiver, tree.Routes[1].Receiver},
		[]string{"team-idm-dev-gcp", "team-tsm-dev-gcp"},
	) {
		t.Fatalf("team routes were not both retained: %+v", tree.Routes)
	}
}

func TestNotificationPolicyHTTPProvenance(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	tree := &models.Route{
		Receiver:   "default",
		Provenance: models.Provenance("api"),
		Routes: []*models.Route{{
			Receiver:          "manual-tsm",
			ObjectMatchers:    models.ObjectMatchers{{"team", "=", "tsm"}},
			MuteTimeIntervals: []string{"night"},
		}},
	}
	var wrote atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/provisioning/policies" {
			t.Errorf("unexpected policy path %q", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(tree); err != nil {
				t.Error(err)
			}
		case http.MethodPut:
			wrote.Store(true)
			if got := r.Header.Get("X-Disable-Provenance"); got != "true" {
				t.Errorf("X-Disable-Provenance = %q, want true", got)
			}
			var submitted models.Route
			if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
				t.Error(err)
			} else if len(submitted.Routes) != 2 || !reflect.DeepEqual(submitted.Routes[0], tree.Routes[0]) {
				t.Errorf("existing route changed in policy PUT: %+v", submitted.Routes)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			if _, err := w.Write([]byte(`{"message":"ok"}`)); err != nil {
				t.Error(err)
			}
		default:
			t.Errorf("unexpected policy method %q", r.Method)
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := grafanaclient.NewHTTPClientWithConfig(strfmt.Default, &grafanaclient.TransportConfig{
		Host: endpoint.Host, Schemes: []string{endpoint.Scheme}, BasePath: "/api",
	})
	baseline, err := client.Provisioning.GetPolicyTree()
	if err != nil {
		t.Fatal(err)
	}
	reconciler := New(nil, nil, nil, nil, nil, nil, nil, client.Provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
	if err := reconciler.updateNotificationPolicy(ctx, "idm", []*protoapi.TeamEnvironment{{
		EnvironmentName: "dev-gcp", SlackAlertsChannel: "#idm",
	}}, baseline.Payload, log); err != nil {
		t.Fatal(err)
	}
	if !wrote.Load() {
		t.Fatal("expected a policy PUT")
	}
}

func TestNotificationRoutesOnDelete(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	team := &protoapi.Team{Slug: "idm"}

	t.Run("disabled flag never reads the policy tree", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		teams := NewMockTeamsClientService(t)
		teams.EXPECT().SearchTeams(&grafanateams.SearchTeamsParams{
			Query: &team.Slug, Context: ctx,
		}).Return(&grafanateams.SearchTeamsOK{
			Payload: &models.SearchTeamQueryResult{},
		}, nil).Once()
		reconciler := New(nil, teams, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook")
		if err := reconciler.Delete(ctx, &apiclient.APIClient{}, team, log); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("existing team route blocks deletion without writing the tree", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		provisioning.EXPECT().GetPolicyTree().Return(&grafanaprovisioning.GetPolicyTreeOK{
			Payload: &models.Route{Provenance: models.Provenance("api"), Routes: []*models.Route{{
				Receiver: "manual", ObjectMatchers: models.ObjectMatchers{{"team", "=", "idm"}},
			}}},
		}, nil).Once()
		reconciler := New(nil, NewMockTeamsClientService(t), nil, nil, nil, nil, nil, provisioning,
			config.FeatureFlags{EnableGrafanaAlerts: true}, "webhook")
		if err := reconciler.Delete(ctx, &apiclient.APIClient{}, team, log); err == nil || !strings.Contains(err.Error(), "manual cleanup") {
			t.Fatalf("expected a manual cleanup error, got %v", err)
		}
	})

	t.Run("failed policy read blocks team deletion", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		provisioning.EXPECT().GetPolicyTree().Return(nil, errors.New("policy read failed")).Once()
		reconciler := New(nil, NewMockTeamsClientService(t), nil, nil, nil, nil, nil, provisioning,
			config.FeatureFlags{EnableGrafanaAlerts: true}, "webhook")
		if err := reconciler.Delete(ctx, &apiclient.APIClient{}, team, log); err == nil || !strings.Contains(err.Error(), "policy read failed") {
			t.Fatalf("expected a policy read error, got %v", err)
		}
	})

	t.Run("nested team route blocks deletion", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		provisioning.EXPECT().GetPolicyTree().Return(&grafanaprovisioning.GetPolicyTreeOK{
			Payload: &models.Route{Routes: []*models.Route{{Routes: []*models.Route{{
				ObjectMatchers: models.ObjectMatchers{{"team", "=", "idm"}},
			}}}}},
		}, nil).Once()
		reconciler := New(nil, NewMockTeamsClientService(t), nil, nil, nil, nil, nil, provisioning,
			config.FeatureFlags{EnableGrafanaAlerts: true}, "webhook")
		if err := reconciler.Delete(ctx, &apiclient.APIClient{}, team, log); err == nil || !strings.Contains(err.Error(), "manual migration") {
			t.Fatalf("expected a nested route conflict, got %v", err)
		}
	})

	t.Run("regex routes use full team matches", func(t *testing.T) {
		for _, tt := range []struct {
			name    string
			op      string
			blocked bool
		}{
			{"substring regex", "=~", false},
			{"negated substring regex", "!~", true},
		} {
			t.Run(tt.name, func(t *testing.T) {
				provisioning := NewMockProvisioningClientService(t)
				provisioning.EXPECT().GetPolicyTree().Return(&grafanaprovisioning.GetPolicyTreeOK{
					Payload: &models.Route{Routes: []*models.Route{{
						Receiver: "manual", ObjectMatchers: models.ObjectMatchers{{"team", tt.op, "idm"}},
					}}},
				}, nil).Once()
				reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning,
					config.FeatureFlags{EnableGrafanaAlerts: true}, "webhook").(*grafanaReconciler)
				err := reconciler.ensureNoNotificationRoutes("idm-dev")
				if (err != nil) != tt.blocked {
					t.Fatalf("ensureNoNotificationRoutes() error = %v, want blocked = %v", err, tt.blocked)
				}
			})
		}
	})
}
