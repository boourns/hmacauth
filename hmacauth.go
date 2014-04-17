package hmacauth

import (
  "crypto/hmac"
  "crypto/sha1"
  "strings"
  "errors"
  "encoding/base64"
  "encoding/hex"
  "net/http"
  "fmt"
)

type Handler struct {
  Key string
  Param string
}

type Message struct {
  Message string
  MAC string
  Deserialized string
}

func parseToken(token []byte) (*Message, error) {
    parts := strings.Split(string(token), "--")
    if len(parts) != 2 {
       return nil, errors.New("Could not parse token into (message, MAC)")
    }

    deserialized, err := base64.StdEncoding.DecodeString(parts[0])
    if err != nil {
       return nil, fmt.Errorf("Error decoding %s: %s", parts[0], err)
    }

    return &Message{Message: parts[0], MAC: parts[1], Deserialized: string(deserialized)}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
  
}

func (h *Handler) isValid(message *Message) bool {
	mac := hmac.New(sha1.New, []byte(h.Key))
	mac.Write([]byte(message.Message))
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(message.MAC), []byte(expectedMAC))
} 

