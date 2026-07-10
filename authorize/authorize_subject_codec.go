package authorize

import (
	"encoding/base64"
	"encoding/json"
)

// TokenSubject represents both the subject and connId which is returned
// as the "sub" claim in the Id Token.
type TokenSubject struct {
	Sub    string `json:"Sub,omitempty"`
	ConnId string `json:"connId,omitempty"`
}

// Marshal converts a message to a URL legal string.
func Marshal(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// Unmarshal decodes a message.
func Unmarshal(s string, v any) error {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
