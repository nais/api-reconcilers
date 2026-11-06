package grafana_reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/go-openapi/strfmt"
	grafanaclient "github.com/grafana/grafana-openapi-client-go/client"
	grafanaprovisioning "github.com/grafana/grafana-openapi-client-go/client/provisioning"
	"github.com/grafana/grafana-openapi-client-go/models"
	"github.com/nais/api-reconcilers/internal/cmd/reconciler/config"
	"github.com/nais/api/pkg/apiclient/protoapi"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
)

func TestContactPointUID(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"team-nais-prod-gcp", "team-nais-prod-gcp"},
		{strings.Repeat("a", 39), strings.Repeat("a", 39)},
		{strings.Repeat("a", 40), strings.Repeat("a", 40)},
		{"team-eessi-nasjonalefellestjenester-dev-fss", "team-9574c382cfcdcc6c80c2cf2c1d4be81d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := contactPointUID(tt.name); got != tt.want {
				t.Fatalf("contactPointUID() = %q, want %q", got, tt.want)
			}
		})
	}

	seen := make(map[string]bool)
	for _, name := range []string{
		strings.Repeat("a", 41),
		"team-eessi-nasjonalefellestjenester-dev-fss",
		"team-eessi-nasjonalefellestjenester-prod-fss",
		"team-salesforce-arbeidsgiver-admin-dev-fss",
		"team-permittering-og-nedbemanning-dev-fss",
		"team-personvernkonsekvensvurdering-dev-fss",
		"team-team-registerforvaltning-rpa-dev-fss",
	} {
		uid := contactPointUID(name)
		if len(uid) != 37 || len(uid) > 40 || !regexp.MustCompile(`^team-[0-9a-f]{32}$`).MatchString(uid) {
			t.Fatalf("invalid hashed UID %q for %q", uid, name)
		}
		if uid != contactPointUID(name) || seen[uid] {
			t.Fatalf("unstable or duplicate UID %q for %q", uid, name)
		}
		seen[uid] = true
	}
}

func TestCreateContactPointUID(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	for _, name := range []string{
		"team-nais-prod-gcp",
		strings.Repeat("a", 40),
		strings.Repeat("a", 41),
		"team-eessi-nasjonalefellestjenester-dev-fss",
	} {
		t.Run(name, func(t *testing.T) {
			provisioning := NewMockProvisioningClientService(t)
			provisioning.EXPECT().GetContactpoints(mock.MatchedBy(func(params *grafanaprovisioning.GetContactpointsParams) bool {
				return params.Context == ctx && params.Name != nil && *params.Name == name
			})).Return(&grafanaprovisioning.GetContactpointsOK{}, nil).Once()
			provisioning.EXPECT().PostContactpoints(mock.MatchedBy(func(params *grafanaprovisioning.PostContactpointsParams) bool {
				return params.Context == ctx && params.Body.UID == contactPointUID(name) &&
					len(params.Body.UID) <= 40 && params.Body.Name == name &&
					params.Body.Type != nil && *params.Body.Type == contactPointType &&
					params.Body.Settings.(map[string]any)["recipient"] == "#alerts"
			})).Return(&grafanaprovisioning.PostContactpointsAccepted{}, nil).Once()
			reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
			if err := reconciler.createOrUpdateContactPoint(ctx, name, "#alerts", log); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUpdateContactPointUID(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	cpType := contactPointType
	longName := "team-eessi-nasjonalefellestjenester-dev-fss"
	for _, tt := range []struct {
		name   string
		points []*models.EmbeddedContactPoint
		uid    string
	}{
		{"team-nais-prod-gcp", []*models.EmbeddedContactPoint{{Name: "team-nais-prod-gcp", UID: "team-nais-prod-gcp", Type: &cpType}}, "team-nais-prod-gcp"},
		{longName, []*models.EmbeddedContactPoint{{Name: longName, UID: contactPointUID(longName), Type: &cpType}}, contactPointUID(longName)},
		{longName, []*models.EmbeddedContactPoint{{Name: longName, UID: "existing-slack-uid", Type: &cpType}}, "existing-slack-uid"},
		{"team-nais-prod-gcp", []*models.EmbeddedContactPoint{{Name: "team-nais-prod-gcp", UID: "existing-short-uid", Type: &cpType}}, "existing-short-uid"},
		{longName, []*models.EmbeddedContactPoint{
			{Name: longName, UID: "other-integration", Type: &cpType},
			{Name: longName, UID: contactPointUID(longName), Type: &cpType},
		}, contactPointUID(longName)},
	} {
		t.Run(tt.uid, func(t *testing.T) {
			provisioning := NewMockProvisioningClientService(t)
			provisioning.EXPECT().GetContactpoints(mock.Anything).Return(&grafanaprovisioning.GetContactpointsOK{Payload: tt.points}, nil).Once()
			provisioning.EXPECT().PutContactpoint(mock.MatchedBy(func(params *grafanaprovisioning.PutContactpointParams) bool {
				return params.Context == ctx && params.UID == tt.uid && params.Body.UID == tt.uid &&
					params.Body.Name == tt.name && params.Body.Settings.(map[string]any)["recipient"] == "#updated"
			})).Return(&grafanaprovisioning.PutContactpointAccepted{}, nil).Once()
			reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
			if err := reconciler.createOrUpdateContactPoint(ctx, tt.name, "#updated", log); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestContactPointLookupFailures(t *testing.T) {
	cpType, otherType := contactPointType, "email"
	name := "team-nais-prod-gcp"
	for _, tt := range []struct {
		name   string
		points []*models.EmbeddedContactPoint
		err    error
		nilRes bool
	}{
		{name: "lookup denied", err: errors.New("forbidden")},
		{name: "empty response", nilRes: true},
		{name: "null integration", points: []*models.EmbeddedContactPoint{nil}},
		{name: "missing UID", points: []*models.EmbeddedContactPoint{{Name: name, Type: &cpType}}},
		{name: "oversized UID", points: []*models.EmbeddedContactPoint{{Name: name, UID: strings.Repeat("a", 41), Type: &cpType}}},
		{name: "unexpected name", points: []*models.EmbeddedContactPoint{{Name: "other", UID: "other", Type: &cpType}}},
		{name: "wrong type", points: []*models.EmbeddedContactPoint{{Name: name, UID: name, Type: &otherType}}},
		{name: "missing type", points: []*models.EmbeddedContactPoint{{Name: name, UID: name}}},
		{name: "ambiguous integrations", points: []*models.EmbeddedContactPoint{
			{Name: name, UID: "one", Type: &cpType}, {Name: name, UID: "two", Type: &cpType},
		}},
		{name: "duplicate expected UID", points: []*models.EmbeddedContactPoint{
			{Name: name, UID: name, Type: &cpType}, {Name: name, UID: name, Type: &cpType},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provisioning := NewMockProvisioningClientService(t)
			var resp *grafanaprovisioning.GetContactpointsOK
			if !tt.nilRes {
				resp = &grafanaprovisioning.GetContactpointsOK{Payload: tt.points}
			}
			provisioning.EXPECT().GetContactpoints(mock.Anything).Return(resp, tt.err).Once()
			reconciler := New(nil, nil, nil, nil, nil, nil, nil, provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
			log, _ := test.NewNullLogger()
			if err := reconciler.createOrUpdateContactPoint(context.Background(), name, "#alerts", log); err == nil {
				t.Fatal("expected lookup failure without creating or updating any contact point")
			}
		})
	}
}

func TestLongContactPointHTTP(t *testing.T) {
	const name = "team-eessi-nasjonalefellestjenester-dev-fss"
	var stored *models.EmbeddedContactPoint
	posts, puts := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/provisioning/contact-points" {
			if r.URL.Query().Get("name") != name {
				t.Error("contact point lookup must use the full name")
			}
			points := []*models.EmbeddedContactPoint{}
			if stored != nil {
				points = append(points, stored)
			}
			if err := json.NewEncoder(w).Encode(points); err != nil {
				t.Error(err)
			}
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/provisioning/contact-points":
			posts++
		case r.Method == http.MethodPut && stored != nil && r.URL.Path == "/api/v1/provisioning/contact-points/"+stored.UID:
			puts++
		default:
			t.Errorf("unexpected contact point request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		var point models.EmbeddedContactPoint
		if err := json.NewDecoder(r.Body).Decode(&point); err != nil {
			t.Error(err)
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if len(point.UID) > 40 || point.UID != contactPointUID(name) || point.Name != name {
			t.Errorf("invalid contact point identity: %q, %q", point.UID, point.Name)
			http.Error(w, "invalid UID or name", http.StatusBadRequest)
			return
		}
		stored = &point
		w.WriteHeader(http.StatusAccepted)
		if _, err := w.Write([]byte(`{"message":"ok"}`)); err != nil {
			t.Error(err)
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
	reconciler := New(nil, nil, nil, nil, nil, nil, nil, client.Provisioning, config.FeatureFlags{}, "webhook").(*grafanaReconciler)
	log, _ := test.NewNullLogger()
	for _, channel := range []string{"#original", "#updated"} {
		if err := reconciler.createOrUpdateContactPoint(context.Background(), name, channel, log); err != nil {
			t.Fatal(err)
		}
	}
	if posts != 1 || puts != 1 || stored == nil || stored.Settings.(map[string]any)["recipient"] != "#updated" {
		t.Fatalf("expected one creation and one update, got %d POSTs and %d PUTs", posts, puts)
	}
	routes := reconciler.buildNotificationRoutes("eessi-nasjonalefellestjenester", []*protoapi.TeamEnvironment{{
		EnvironmentName: "dev-fss", SlackAlertsChannel: "#updated",
	}}, log)
	if len(routes) != 1 || routes[0].Receiver != name {
		t.Fatal("policy receiver must retain the full contact point name")
	}
}
