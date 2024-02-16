package gcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

type (
	Clusters map[string]Cluster
	Cluster  struct {
		TeamsFolderID int64
		ProjectID     string
	}
)

var _ json.Unmarshaler = (*Clusters)(nil)

func (c *Clusters) UnmarshalJSON(value []byte) error {
	if len(value) == 0 {
		return nil
	}
	clustersWithStringID := make(map[string]struct {
		TeamsFolderID string `json:"teams_folder_id"`
		ProjectID     string `json:"project_id"`
	})

	*c = make(Clusters)
	err := json.NewDecoder(bytes.NewReader(value)).Decode(&clustersWithStringID)
	if err != nil {
		return fmt.Errorf("parse GCP cluster info: %w", err)
	}

	for environment, cluster := range clustersWithStringID {
		folderID, err := strconv.ParseInt(cluster.TeamsFolderID, 10, 64)
		if err != nil {
			return fmt.Errorf("parse GCP cluster info's folder ID: %w", err)
		}
		(*c)[environment] = Cluster{
			TeamsFolderID: folderID,
			ProjectID:     cluster.ProjectID,
		}
	}
	return nil
}
