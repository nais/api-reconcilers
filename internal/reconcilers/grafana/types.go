package grafana_reconciler

import "net/http"

type grafanaReconciler struct {
	httpClient          *http.Client
	endpoint            string
	serviceAccountToken string
}

type Client interface{}
