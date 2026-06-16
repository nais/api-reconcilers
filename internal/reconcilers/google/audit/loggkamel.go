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

type OnPremPostgresLogClient interface {
	RequiresOnPremPostgresLogging(ctx context.Context, teamSlug string) (bool, error)
}

type loggkamelClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewLoggkamelClientForTesting(baseURL string) OnPremPostgresLogClient {
	return newLoggkamelClient(baseURL)
}

func newLoggkamelClient(baseURL string) *loggkamelClient {
	return &loggkamelClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *loggkamelClient) RequiresOnPremPostgresLogging(ctx context.Context, teamSlug string) (bool, error) {
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
