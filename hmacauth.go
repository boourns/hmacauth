package hmacauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type handler struct {
	Key   string
	Param string
}

type message struct {
	message string
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

	return &message{message: parts[0], MAC: parts[1], Decoded: string(decoded)}, nil
}

func Authenticate(key string, param string, fn func(http.ResponseWriter, *http.Request, map[string]string)) http.HandlerFunc {
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
		fn(w, r, auth.Decoded)
	}
}

func (h *handler) isValid(message *message) bool {
	mac := hmac.New(sha1.New, []byte(h.Key))
	mac.Write([]byte(message.message))
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(message.MAC), []byte(expectedMAC))
}
