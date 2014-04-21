package hmacauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

type handler struct {
	Key   string
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

func Authenticate(key string, param string, fn func(http.ResponseWriter, *http.Request, []int64)) http.HandlerFunc {
	handler := &handler{Key: key, Param: param}

	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			log.Printf("Couldn't parse form from request")
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		token := r.Form[handler.Param]
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

		var parsed []int64
		err = json.Unmarshal([]byte(auth.Decoded), &parsed)
		if err != nil {
			log.Printf("Couldn't demarshal form token: %s", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		if parsed[0] < time.Now().Unix() {
			log.Printf("Token %v is expired (timestamp = %v)", token, parsed[0])
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		fn(w, r, parsed)
	}
}

func (h *handler) isValid(message *message) bool {
	expectedMAC := h.Calculate(message.Message)
	return hmac.Equal([]byte(message.MAC), []byte(expectedMAC))
}

func (h *handler) Calculate(message string) string {
	mac := hmac.New(sha1.New, []byte(h.Key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
