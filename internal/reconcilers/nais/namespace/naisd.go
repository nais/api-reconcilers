package nais_namespace_reconciler

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/nais/api/pkg/protoapi"
)

const (
	naisdTopicPrefix = "naisd-console-"
	createNamespace  = "create-namespace"
	deleteNamespace  = "delete-namespace"
)

type NaisdCreateNamespace struct {
	Name               string `json:"name"`
	GcpProject         string `json:"gcpProject"` // the user-specified "project id"; not the "projects/ID" format
	GroupEmail         string `json:"groupEmail"`
	AzureGroupID       string `json:"azureGroupID"`
	CNRMEmail          string `json:"cnrmEmail"`
	SlackAlertsChannel string `json:"slackAlertsChannel"`
}

type NaisdDeleteNamespace struct {
	Name string `json:"name"`
}

type NaisdRequest struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func createNamespacePayload(naisTeam *protoapi.Team, env *protoapi.TeamEnvironment, azureGroupID uuid.UUID) ([]byte, error) {
	cnrmEmail, gcpProjectID := "", ""
	if env.GcpProjectId != nil {
		gcpProjectID = *env.GcpProjectId
		cnrmEmail = "nais-sa-cnrm@" + gcpProjectID + ".iam.gserviceaccount.com"
	}

	var gge string
	if naisTeam.GoogleGroupEmail != nil {
		gge = *naisTeam.GoogleGroupEmail
	}
	createReq, err := json.Marshal(
		NaisdCreateNamespace{
			Name:       naisTeam.Slug,
			GcpProject: gcpProjectID,
			GroupEmail: gge,
			AzureGroupID: func(id uuid.UUID) string {
				if id == uuid.Nil {
					return ""
				}
				return id.String()
			}(azureGroupID),
			CNRMEmail:          cnrmEmail,
			SlackAlertsChannel: env.SlackAlertsChannel,
		},
	)
	if err != nil {
		return []byte{}, fmt.Errorf("marshal create namespace request: %w", err)
	}

	payload, err := json.Marshal(NaisdRequest{
		Type: createNamespace,
		Data: createReq,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("marshal naisd request envelope: %w", err)
	}

	return payload, nil
}

func deleteNamespacePayload(teamSlug string) ([]byte, error) {
	deleteReq, err := json.Marshal(NaisdDeleteNamespace{
		Name: teamSlug,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("marshal delete namespace request: %w", err)
	}

	payload, err := json.Marshal(NaisdRequest{
		Type: deleteNamespace,
		Data: deleteReq,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("marshal naisd request envelope: %w", err)
	}

	return payload, nil
}
