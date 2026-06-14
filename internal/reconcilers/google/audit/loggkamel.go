package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AuditPolicyClient determines whether a team requires audit logging.
type AuditPolicyClient interface {
	// RequiresAuditLogging returns true if the given team is an active nais team
	// that requires audit logging according to loggkamel.
	RequiresAuditLogging(ctx context.Context, teamSlug string) (bool, error)
}

// loggkamelClient is an AuditPolicyClient backed by the loggkamel HTTP API.
//
// It queries the NaisteamController "findAllActiveNaisteam" style endpoint:
//
//	GET <baseURL>/api/v1/naisteam/active/<teamSlug>
//
// which returns a JSON boolean (true/false). The base URL differs between
// environments (e.g. it contains ".dev." for dev and omits it for prod) and is
// therefore configurable via the helm chart / fasit.
type loggkamelClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewLoggkamelClientForTesting exposes the loggkamel client for tests.
func NewLoggkamelClientForTesting(baseURL string) AuditPolicyClient {
	return newLoggkamelClient(baseURL)
}

// newLoggkamelClient creates a new loggkamel-backed AuditPolicyClient.
func newLoggkamelClient(baseURL string) *loggkamelClient {
	return &loggkamelClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// RequiresAuditLogging calls the loggkamel active naisteam endpoint for the team.
func (c *loggkamelClient) RequiresAuditLogging(ctx context.Context, teamSlug string) (bool, error) {
	endpoint := fmt.Sprintf("%s/api/v1/naisteam/active/%s", c.baseURL, url.PathEscape(teamSlug))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("create loggkamel request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("call loggkamel for team %s: %w", teamSlug, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code %d from loggkamel for team %s", resp.StatusCode, teamSlug)
	}

	var requires bool
	if err := json.NewDecoder(resp.Body).Decode(&requires); err != nil {
		return false, fmt.Errorf("decode loggkamel response for team %s: %w", teamSlug, err)
	}

	return requires, nil
}


