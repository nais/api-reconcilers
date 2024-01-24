package nais_namespace_reconciler

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

const (
	naisdTopicPrefix = "naisd-console-"
	createNamespace  = "create-namespace"
	deleteNamespace  = "delete-namespace"
)

type naisdCreateNamespace struct {
	Name               string `json:"name"`
	GcpProject         string `json:"gcpProject"` // the user-specified "project id"; not the "projects/ID" format
	GroupEmail         string `json:"groupEmail"`
	AzureGroupID       string `json:"azureGroupID"`
	CNRMEmail          string `json:"cnrmEmail"`
	SlackAlertsChannel string `json:"slackAlertsChannel"`
}

type naisdDeleteNamespace struct {
	Name string `json:"name"`
}

type naisdRequest struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func createNamespacePayload(teamSlug, gcpProjectID, groupEmail, slackAlertsChannel, cnrmServiceAccountID string, azureGroupID uuid.UUID) ([]byte, error) {
	cnrmEmail := ""
	if gcpProjectID != "" {
		cnrmEmail = cnrmServiceAccountID + "@" + gcpProjectID + ".iam.gserviceaccount.com"
	}

	createReq, err := json.Marshal(
		naisdCreateNamespace{
			Name:       teamSlug,
			GcpProject: gcpProjectID,
			GroupEmail: groupEmail,
			AzureGroupID: func(id uuid.UUID) string {
				if id == uuid.Nil {
					return ""
				}
				return id.String()
			}(azureGroupID),
			CNRMEmail:          cnrmEmail,
			SlackAlertsChannel: slackAlertsChannel,
		},
	)
	if err != nil {
		return []byte{}, fmt.Errorf("marshal create namespace request: %w", err)
	}

	payload, err := json.Marshal(naisdRequest{
		Type: createNamespace,
		Data: createReq,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("marshal naisd request envelope: %w", err)
	}

	return payload, nil
}

func deleteNamespacePayload(teamSlug string) ([]byte, error) {
	deleteReq, err := json.Marshal(naisdDeleteNamespace{
		Name: teamSlug,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("marshal delete namespace request: %w", err)
	}

	payload, err := json.Marshal(naisdRequest{
		Type: deleteNamespace,
		Data: deleteReq,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("marshal naisd request envelope: %w", err)
	}

	return payload, nil
}
