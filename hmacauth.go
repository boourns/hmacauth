package hmacauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type handler struct {
	Keys  []string
	Param string
}

type message struct {
	Message string
	MAC     string
	Decoded string
}

func parseToken(token string) (*message, error) {
	parts := strings.Split(token, "--")
	if len(parts) != 2 {
		return nil, errors.New("Could not parse token into (message, MAC)")
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("Error decoding %s: %s", parts[0], err)
	}

	return &message{Message: parts[0], MAC: parts[1], Decoded: string(decoded)}, nil
}

func Authenticate(keys []string, param string, fn func(http.ResponseWriter, *http.Request, []json.RawMessage)) http.HandlerFunc {
	handler := &handler{Keys: keys, Param: param}

	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query()[handler.Param]
		if token == nil || len(token) != 1 {
			log.Printf("Couldn't find param %v in request", handler.Param)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		auth, err := parseToken(token[0])
		if err != nil {
			log.Printf("Couldn't parse form token")
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		if handler.isValid(auth) == false {
			log.Printf("Token %v is invalid", token)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		var parsed []json.RawMessage
		err = json.Unmarshal([]byte(auth.Decoded), &parsed)
		if err != nil {
			log.Printf("Couldn't demarshal form token: %s", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		if len(parsed) < 1 {
			log.Printf("No timestamp given")
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		var timestamp int64
		err = json.Unmarshal(parsed[0], &timestamp)
		if err != nil {
			log.Printf("Failed to decode timestamp as int", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		if timestamp < time.Now().Unix() {
			log.Printf("Token %v is expired (timestamp = %v)", token, timestamp)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		fn(w, r, parsed)
	}
}

func (h *handler) isValid(message *message) bool {
	for _, key := range h.Keys {
		expectedMAC := Calculate(message.Message, key)
		if hmac.Equal([]byte(message.MAC), []byte(expectedMAC)) {
			return true
		}
	}
	return false
}

func Calculate(message string, key string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
