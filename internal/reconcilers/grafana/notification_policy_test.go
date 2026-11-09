package grafana_reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-openapi/strfmt"
	grafanaclient "github.com/grafana/grafana-openapi-client-go/client"
	grafanaprovisioning "github.com/grafana/grafana-openapi-client-go/client/provisioning"
	"github.com/grafana/grafana-openapi-client-go/models"
	"github.com/nais/api-reconcilers/internal/cmd/reconciler/config"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
)

func expectDiscardMuteTiming(provisioning *MockProvisioningClientService) {
	provisioning.EXPECT().GetMuteTimingsWithParams(mock.Anything).Return(&grafanaprovisioning.GetMuteTimingsOK{
		Payload: models.MuteTimings{{
			Name: discardMuteTiming,
			TimeIntervals: []*models.TimeIntervalItem{{
				Times: []*models.TimeIntervalTimeRange{{StartTime: "00:00", EndTime: "24:00"}},
			}},
		}},
	}, nil)
}

func TestTeamNotificationHierarchy(t *testing.T) {
	log, _ := test.NewNullLogger()
	reconciler := &grafanaReconciler{}
	environments := []*protoapi.TeamEnvironment{
		{EnvironmentName: "dev-gcp", SlackAlertsChannel: "#traktor-dev"},
		{EnvironmentName: "prod-gcp", SlackAlertsChannel: "#traktor-prod"},
		{EnvironmentName: "dev-fss", SlackAlertsChannel: "#traktor-dev"},
		{EnvironmentName: "prod-fss", SlackAlertsChannel: "#traktor-prod"},
		{EnvironmentName: "unused"},
	}
	flat := reconciler.buildNotificationRoutes("traktor", environments, log)
	before := &models.Route{Receiver: "before", Continue: true, Routes: []*models.Route{{Receiver: "nested"}}}
	after := &models.Route{Receiver: "after", MuteTimeIntervals: []string{"night"}}
	existing := append([]*models.Route{before}, flat...)
	existing = append(existing, after)
	snapshot, err := json.Marshal(existing)
	if err != nil {
		t.Fatal(err)
	}
	planned, err := planTeamNotificationRoutes(existing, flat, "traktor")
	if err != nil {
		t.Fatal(err)
	}
	if len(planned) != 3 || planned[0] != before || planned[2] != after {
		t.Fatalf("unrelated route order changed: %+v", planned)
	}
	parent := planned[1]
	if !reflect.DeepEqual(parent.ObjectMatchers, models.ObjectMatchers{{"team", "=", "traktor"}}) ||
		parent.Receiver != "" || parent.Continue || len(parent.Routes) != 5 {
		t.Fatalf("unexpected team parent: %+v", parent)
	}
	for i, env := range environments[:4] {
		child := parent.Routes[i]
		if !reflect.DeepEqual(child.ObjectMatchers, models.ObjectMatchers{{"env", "=", env.EnvironmentName}}) ||
			child.Receiver != "team-traktor-"+env.EnvironmentName ||
			child.Continue || len(child.MuteTimeIntervals) != 0 ||
			!reflect.DeepEqual(child.GroupBy, flat[i].GroupBy) ||
			child.GroupWait != flat[i].GroupWait || child.GroupInterval != flat[i].GroupInterval ||
			child.RepeatInterval != flat[i].RepeatInterval {
			t.Fatalf("unexpected environment child: %+v", child)
		}
	}
	fallback := parent.Routes[4]
	if !sameNotificationRoute(fallback, &models.Route{MuteTimeIntervals: []string{discardMuteTiming}}) {
		t.Fatalf("unexpected discard fallback: %+v", fallback)
	}
	for _, env := range []string{"", "unknown", "unused"} {
		for _, child := range parent.Routes[:4] {
			if child.ObjectMatchers[0][2] == env {
				t.Fatalf("environment %q must reach the muted fallback", env)
			}
		}
	}
	afterSnapshot, err := json.Marshal(existing)
	if err != nil || string(snapshot) != string(afterSnapshot) {
		t.Fatal("planning mutated the original tree")
	}
	again, err := planTeamNotificationRoutes(planned, flat, "traktor")
	if err != nil || again != nil {
		t.Fatalf("unchanged hierarchy should not be rewritten: %v, %v", again, err)
	}

	t.Run("adds environments before the fallback without mutating the parent", func(t *testing.T) {
		initial, err := planTeamNotificationRoutes(nil, flat[:1], "traktor")
		if err != nil {
			t.Fatal(err)
		}
		updated, err := planTeamNotificationRoutes(initial, flat, "traktor")
		if err != nil || len(updated) != 1 || len(updated[0].Routes) != 5 ||
			len(initial[0].Routes) != 2 || updated[0].Routes[0] != initial[0].Routes[0] {
			t.Fatalf("unexpected added environments: %+v, %v", updated, err)
		}
	})

	t.Run("team without channels discards all policy routed alerts", func(t *testing.T) {
		planned, err := planTeamNotificationRoutes(nil, nil, "traktor")
		if err != nil || len(planned) != 1 || len(planned[0].Routes) != 1 ||
			!sameNotificationRoute(planned[0].Routes[0], fallback) {
			t.Fatalf("unexpected fallback-only parent: %+v, %v", planned, err)
		}
	})
}

func TestTeamNotificationHierarchyConflicts(t *testing.T) {
	log, _ := test.NewNullLogger()
	desired := (&grafanaReconciler{}).buildNotificationRoutes("idm", []*protoapi.TeamEnvironment{
		{EnvironmentName: "dev-gcp", SlackAlertsChannel: "#idm"},
		{EnvironmentName: "prod-gcp", SlackAlertsChannel: "#idm"},
	}, log)
	nested, err := planTeamNotificationRoutes(nil, desired, "idm")
	if err != nil {
		t.Fatal(err)
	}
	withoutFallback := *nested[0]
	withoutFallback.Routes = withoutFallback.Routes[:2]
	changedParent := *nested[0]
	changedParent.Continue = true
	changedChild := *nested[0]
	changedChild.Routes = slices.Clone(changedChild.Routes)
	child := *changedChild.Routes[0]
	child.GroupWait = "1m"
	changedChild.Routes[0] = &child
	duplicateChild := *nested[0]
	duplicateChild.Routes = []*models.Route{nested[0].Routes[0], nested[0].Routes[0], nested[0].Routes[2]}
	tests := []struct {
		name     string
		existing []*models.Route
		desired  []*models.Route
	}{
		{"missing fallback", []*models.Route{&withoutFallback}, desired},
		{"changed parent", []*models.Route{&changedParent}, desired},
		{"changed child", []*models.Route{&changedChild}, desired},
		{"duplicate parent", []*models.Route{nested[0], nested[0]}, desired},
		{"duplicate child", []*models.Route{&duplicateChild}, desired},
		{"removed environment", nested, desired[:1]},
		{"all environments removed", nested, nil},
		{"mixed layouts", []*models.Route{nested[0], desired[0]}, desired},
		{"interleaved flat routes", []*models.Route{desired[0], {Receiver: "manual"}, desired[1]}, desired},
		{"receiver reused outside team", []*models.Route{nested[0], {Receiver: desired[0].Receiver}}, desired},
		{"receiver reused in nested unrelated route", []*models.Route{nested[0], {Routes: []*models.Route{{Receiver: desired[0].Receiver}}}}, desired},
		{"nested team parent", []*models.Route{{Routes: nested}}, desired},
		{"duplicate desired environment", nil, []*models.Route{desired[0], desired[0]}},
		{"nil route", []*models.Route{nil}, desired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := planTeamNotificationRoutes(tt.existing, tt.desired, "idm"); err == nil {
				t.Fatal("expected manual migration conflict")
			}
		})
	}
}

func TestDiscardMuteTiming(t *testing.T) {
	ctx := context.Background()
	t.Run("accepts equivalent empty restrictions and timezone", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		provisioning.EXPECT().GetMuteTimingsWithParams(mock.Anything).Return(&grafanaprovisioning.GetMuteTimingsOK{
			Payload: models.MuteTimings{{
				Name: discardMuteTiming,
				TimeIntervals: []*models.TimeIntervalItem{{
					Times:       []*models.TimeIntervalTimeRange{{StartTime: "00:00", EndTime: "24:00"}},
					DaysOfMonth: []string{}, Months: []string{}, Weekdays: []string{}, Years: []string{},
					Location: "Europe/Oslo",
				}},
			}},
		}, nil).Once()
		if err := (&grafanaReconciler{provisioning: provisioning}).ensureDiscardMuteTiming(ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("creates an all-day interval before the policy can reference it", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		provisioning.EXPECT().GetMuteTimingsWithParams(mock.Anything).Return(&grafanaprovisioning.GetMuteTimingsOK{}, nil).Once()
		provisioning.EXPECT().PostMuteTiming(mock.MatchedBy(func(params *grafanaprovisioning.PostMuteTimingParams) bool {
			return params.Context == ctx && params.XDisableProvenance == nil &&
				params.Body.Name == discardMuteTiming && len(params.Body.TimeIntervals) == 1 &&
				reflect.DeepEqual(params.Body.TimeIntervals[0], &models.TimeIntervalItem{
					Times: []*models.TimeIntervalTimeRange{{StartTime: "00:00", EndTime: "24:00"}},
				})
		})).Return(&grafanaprovisioning.PostMuteTimingCreated{}, nil).Once()
		if err := (&grafanaReconciler{provisioning: provisioning}).ensureDiscardMuteTiming(ctx); err != nil {
			t.Fatal(err)
		}
	})
	for _, tt := range []struct {
		name string
		resp *grafanaprovisioning.GetMuteTimingsOK
		err  error
	}{
		{"read fails", nil, errors.New("forbidden")},
		{"empty response", nil, nil},
		{"null interval", &grafanaprovisioning.GetMuteTimingsOK{Payload: models.MuteTimings{nil}}, nil},
		{"changed interval", &grafanaprovisioning.GetMuteTimingsOK{Payload: models.MuteTimings{{Name: discardMuteTiming}}}, nil},
		{"restricted days", &grafanaprovisioning.GetMuteTimingsOK{Payload: models.MuteTimings{{
			Name: discardMuteTiming, TimeIntervals: []*models.TimeIntervalItem{{
				Times:    []*models.TimeIntervalTimeRange{{StartTime: "00:00", EndTime: "24:00"}},
				Weekdays: []string{"monday:friday"},
			}},
		}}}, nil},
		{"partial day", &grafanaprovisioning.GetMuteTimingsOK{Payload: models.MuteTimings{{
			Name: discardMuteTiming, TimeIntervals: []*models.TimeIntervalItem{{
				Times: []*models.TimeIntervalTimeRange{{StartTime: "00:00", EndTime: "23:59"}},
			}},
		}}}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provisioning := NewMockProvisioningClientService(t)
			provisioning.EXPECT().GetMuteTimingsWithParams(mock.Anything).Return(tt.resp, tt.err).Once()
			if err := (&grafanaReconciler{provisioning: provisioning}).ensureDiscardMuteTiming(ctx); err == nil {
				t.Fatal("expected an explicit error without creating or updating the interval")
			}
		})
	}
	t.Run("creation failure prevents a policy write", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		provisioning.EXPECT().GetPolicyTree().Return(&grafanaprovisioning.GetPolicyTreeOK{Payload: &models.Route{Receiver: "default"}}, nil).Once()
		provisioning.EXPECT().GetMuteTimingsWithParams(mock.Anything).Return(&grafanaprovisioning.GetMuteTimingsOK{}, nil).Once()
		provisioning.EXPECT().PostMuteTiming(mock.Anything).Return(nil, errors.New("forbidden")).Once()
		log, _ := test.NewNullLogger()
		reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
		if err := reconciler.updateNotificationPolicy(ctx, "idm", nil, &models.Route{Receiver: "default"}, log); err == nil {
			t.Fatal("expected creation failure without writing a policy")
		}
	})
}

func TestNotificationPolicyRejectsInvalidEnvironment(t *testing.T) {
	log, _ := test.NewNullLogger()
	for _, env := range []*protoapi.TeamEnvironment{nil, {SlackAlertsChannel: "#idm"}} {
		reconciler := &grafanaReconciler{provisioning: NewMockProvisioningClientService(t)}
		if _, _, err := reconciler.notificationPolicyChanges(context.Background(), "idm", []*protoapi.TeamEnvironment{env}, log); err == nil {
			t.Fatal("expected invalid environment to fail before any provisioning call")
		}
	}
}

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

func TestStructuredTeamMatcherTypes(t *testing.T) {
	tests := []struct {
		name      string
		matchType models.MatchType
		value     string
		want      bool
		wantError bool
	}{
		{"equal", 0, "nais", true, false},
		{"equal mismatch", 0, "other", false, false},
		{"not equal", 1, "other", true, false},
		{"not equal mismatch", 1, "nais", false, false},
		{"regex", 2, "nais|other", true, false},
		{"regex mismatch", 2, "nai", false, false},
		{"not regex", 3, "other", true, false},
		{"not regex mismatch", 3, "nais|other", false, false},
		{"invalid type", 4, "nais", false, true},
		{"invalid regex", 2, "[", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &models.Route{Matchers: models.Matchers{{Name: "team", Type: tt.matchType, Value: tt.value}}}
			got, err := routeMatchesTeam(route, "nais")
			if (err != nil) != tt.wantError || got != tt.want {
				t.Fatalf("routeMatchesTeam() = %v, %v; want %v, error %v", got, err, tt.want, tt.wantError)
			}
		})
	}
}

func TestTeamRegexMatching(t *testing.T) {
	matcher := func(pattern string, isEqual bool) *models.Matcher {
		matchType := matchRegexp
		if !isEqual {
			matchType = matchNotRegexp
		}
		return &models.Matcher{Name: "team", Value: pattern, Type: matchType}
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
		matchType := matchEqual
		if isRegex {
			matchType = matchRegexp
		}
		if !isEqual {
			matchType++
		}
		return &models.Matcher{Name: "team", Value: value, Type: matchType}
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
			_, err := removeTeamNotificationRoutes(&models.Route{Routes: []*models.Route{manual}}, tt.team, make(map[string]bool))
			if (err != nil) != tt.blocked {
				t.Fatalf("removeTeamNotificationRoutes() error = %v, want blocked = %v", err, tt.blocked)
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

	t.Run("appends the team parent and preserves existing children", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		expectDiscardMuteTiming(provisioning)
		existing := &models.Route{
			Receiver:       "tsm",
			ObjectMatchers: models.ObjectMatchers{{"team", "=", "tsm"}},
			Routes:         []*models.Route{{Receiver: "tsm-panic", MuteTimeIntervals: []string{"night"}}},
		}
		tree := &models.Route{Receiver: "default", Routes: []*models.Route{existing}}
		provisioning.EXPECT().GetPolicyTree().
			Return(&grafanaprovisioning.GetPolicyTreeOK{Payload: tree}, nil).Twice()
		provisioning.EXPECT().PutPolicyTree(mock.MatchedBy(func(params *grafanaprovisioning.PutPolicyTreeParams) bool {
			return params.XDisableProvenance == nil &&
				params.Body == tree && len(tree.Routes) == 2 && tree.Routes[0] == existing &&
				len(tree.Routes[1].Routes) == 2 &&
				tree.Routes[1].Routes[0].Receiver == "team-idm-dev-gcp" &&
				len(existing.Routes) == 1 && len(existing.Routes[0].MuteTimeIntervals) == 1
		})).Return(&grafanaprovisioning.PutPolicyTreeAccepted{}, nil).Once()

		reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
		if err := reconciler.updateNotificationPolicy(ctx, "idm", environments, tree, log); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("does not rewrite an unchanged provisioned tree", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		expectDiscardMuteTiming(provisioning)
		reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
		routes, err := planTeamNotificationRoutes(nil, reconciler.buildNotificationRoutes("idm", environments, log), "idm")
		if err != nil {
			t.Fatal(err)
		}
		tree := &models.Route{Provenance: models.Provenance("api"), Routes: routes}
		provisioning.EXPECT().GetPolicyTree().
			Return(&grafanaprovisioning.GetPolicyTreeOK{Payload: tree}, nil).Once()
		if err := reconciler.updateNotificationPolicy(ctx, "idm", environments, tree, log); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("provisions an unchanged unlocked tree without altering routes", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		expectDiscardMuteTiming(provisioning)
		reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
		routes, err := planTeamNotificationRoutes(nil, reconciler.buildNotificationRoutes("idm", environments, log), "idm")
		if err != nil {
			t.Fatal(err)
		}
		other := &models.Route{Receiver: "manual", Continue: true}
		tree := &models.Route{Receiver: "default", Routes: append(routes, other)}
		snapshot, err := json.Marshal(tree)
		if err != nil {
			t.Fatal(err)
		}
		provisioning.EXPECT().GetPolicyTree().
			Return(&grafanaprovisioning.GetPolicyTreeOK{Payload: tree}, nil).Twice()
		provisioning.EXPECT().PutPolicyTree(mock.MatchedBy(func(params *grafanaprovisioning.PutPolicyTreeParams) bool {
			submitted, err := json.Marshal(params.Body)
			return err == nil && params.XDisableProvenance == nil &&
				string(submitted) == string(snapshot) && params.Body.Routes[1] == other
		})).Return(&grafanaprovisioning.PutPolicyTreeAccepted{}, nil).Once()
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
		provisioning.EXPECT().GetContactpoints(mock.Anything).Return(&grafanaprovisioning.GetContactpointsOK{}, nil).Once()
		provisioning.EXPECT().PostContactpoints(mock.Anything).Return(&grafanaprovisioning.PostContactpointsAccepted{}, nil).Once()
		reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
		reconciler.templatesInitialized = true
		err := reconciler.reconcileAlerting(ctx, "idm", environments, log)
		if err == nil || !strings.Contains(err.Error(), "refusing to overwrite external changes") {
			t.Fatalf("expected a stale policy tree error, got %v", err)
		}
	})

	t.Run("rechecks the tree after ensuring the fallback interval", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		expectDiscardMuteTiming(provisioning)
		baseline := &models.Route{Receiver: "default"}
		provisioning.EXPECT().GetPolicyTree().Return(&grafanaprovisioning.GetPolicyTreeOK{Payload: baseline}, nil).Once()
		provisioning.EXPECT().GetPolicyTree().Return(&grafanaprovisioning.GetPolicyTreeOK{
			Payload: &models.Route{Receiver: "changed"},
		}, nil).Once()
		reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
		err := reconciler.updateNotificationPolicy(ctx, "idm", environments, baseline, log)
		if err == nil || !strings.Contains(err.Error(), "refusing to overwrite external changes") {
			t.Fatalf("expected the changed tree to prevent a PUT, got %v", err)
		}
	})
}

func TestNotificationPolicySerializesTeams(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	provisioning := NewMockProvisioningClientService(t)
	expectDiscardMuteTiming(provisioning)
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
	}).Times(6)
	provisioning.EXPECT().GetContactpoints(mock.Anything).Return(&grafanaprovisioning.GetContactpointsOK{}, nil).Twice()
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
		[]string{tree.Routes[0].Routes[0].Receiver, tree.Routes[1].Routes[0].Receiver},
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
		if r.URL.Path == "/api/v1/provisioning/mute-timings" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`[{"name":"nais-unconfigured-environment","time_intervals":[{"times":[{"start_time":"00:00","end_time":"24:00"}]}]}]`))
			if err != nil {
				t.Error(err)
			}
			return
		}
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
			if got := r.Header.Get("X-Disable-Provenance"); got != "" {
				t.Errorf("X-Disable-Provenance = %q, want omitted", got)
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

	t.Run("missing clients fail closed even when alerting is disabled", func(t *testing.T) {
		provisioning := NewMockProvisioningClientService(t)
		teams := NewMockTeamsClientService(t)
		reconciler := New(nil, teams, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook")
		if err := reconciler.Delete(ctx, &apiclient.APIClient{}, team, log); err == nil {
			t.Fatal("expected missing folders client to block deletion")
		}
	})

	t.Run("manual team route blocks deletion", func(t *testing.T) {
		tree := &models.Route{Provenance: models.Provenance("api"), Routes: []*models.Route{{
			Receiver: "manual", ObjectMatchers: models.ObjectMatchers{{"team", "=", "idm"}},
		}}}
		_, err := removeTeamNotificationRoutes(tree, team.Slug, make(map[string]bool))
		if err == nil || len(tree.Routes) != 1 {
			t.Fatalf("expected manual route to block deletion without mutating baseline, got %v", err)
		}
	})

	t.Run("nested team route blocks deletion", func(t *testing.T) {
		tree := &models.Route{Routes: []*models.Route{{Routes: []*models.Route{{
			ObjectMatchers: models.ObjectMatchers{{"team", "=", "idm"}},
		}}}}}
		_, err := removeTeamNotificationRoutes(tree, team.Slug, make(map[string]bool))
		if err == nil || len(tree.Routes[0].Routes) != 1 {
			t.Fatalf("expected nested route to block deletion, got %v", err)
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
				tree := &models.Route{Routes: []*models.Route{{
					Receiver: "manual", ObjectMatchers: models.ObjectMatchers{{"team", tt.op, "idm"}},
				}}}
				_, err := removeTeamNotificationRoutes(tree, "idm-dev", make(map[string]bool))
				if (err != nil) != tt.blocked {
					t.Fatalf("removeTeamNotificationRoutes() error = %v, want blocked = %v", err, tt.blocked)
				}
			})
		}
	})
}
