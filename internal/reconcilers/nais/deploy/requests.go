package nais_deploy_reconciler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type ProvisionApiKeyRequest struct {
	Team      string
	Rotate    bool
	Timestamp int64
}

// getProvisionPayload get a payload for the NAIS deploy key provisioning request
func getProvisionPayload(teamSlug string) ([]byte, error) {
	payload, err := json.Marshal(&ProvisionApiKeyRequest{
		Rotate:    false,
		Team:      teamSlug,
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// genMAC generates the HMAC signature for a message provided the secret key using SHA256
func genMAC(message, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil))
}
