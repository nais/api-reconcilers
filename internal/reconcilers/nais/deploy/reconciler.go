package nais_deploy_reconciler

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/api-reconcilers/internal/reconcilers"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
	"github.com/sirupsen/logrus"
)

const (
	reconcilerName = "nais:deploy"
)

type naisDeployReconciler struct {
	httpClient   *http.Client
	endpoint     string
	provisionKey []byte
}

type OptFunc func(*naisDeployReconciler)

func WithHttpClient(client *http.Client) OptFunc {
	return func(r *naisDeployReconciler) {
		r.httpClient = client
	}
}

func New(endpoint, provisionKey string, opts ...OptFunc) (reconcilers.Reconciler, error) {
	key, err := hex.DecodeString(provisionKey)
	if err != nil {
		return nil, err
	}

	r := &naisDeployReconciler{
		endpoint:     endpoint,
		provisionKey: key,
	}

	for _, opt := range opts {
		opt(r)
	}

	if r.httpClient == nil {
		r.httpClient = http.DefaultClient
	}

	return r, nil
}

func (r *naisDeployReconciler) Configuration() *protoapi.NewReconciler {
	return &protoapi.NewReconciler{
		Name:        r.Name(),
		DisplayName: "NAIS deploy",
		Description: "Provision NAIS deploy key for Console teams.",
		MemberAware: false,
	}
}

func (r *naisDeployReconciler) Name() string {
	return reconcilerName
}

func (r *naisDeployReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	payload, err := getProvisionPayload(naisTeam.Slug)
	if err != nil {
		return fmt.Errorf("create JSON payload for deploy key API: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request for deploy key API: %w", err)
	}

	signature := genMAC(payload, r.provisionKey)
	request.Header.Set("X-NAIS-Signature", signature)
	request.Header.Set("Content-Type", "application/json")

	response, err := r.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusCreated:
		if err := r.saveState(ctx, client, naisTeam.Slug, &naisDeployState{provisioned: time.Now()}); err != nil {
			return err
		}

		return nil
	case http.StatusNoContent:
		return nil
	case http.StatusOK:
		return nil
	default:
		return fmt.Errorf("provision NAIS deploy API key for team %q: %s", naisTeam.Slug, response.Status)
	}
}

func (r *naisDeployReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	_, err := client.ReconcilerResources().Delete(ctx, &protoapi.DeleteReconcilerResourcesRequest{
		ReconcilerName: r.Name(),
		TeamSlug:       naisTeam.Slug,
	})
	if err != nil {
		return err
	}

	return nil
}
