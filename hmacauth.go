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

type handler struct {
  Key string
  Param string
}

type message struct {
  message string
  MAC string
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

func Authenticate(key string, param string, fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
    handler := &handler{Key: key, Param: param}

    return func(w http.ResponseWriter, r *http.Request) {
      err := r.ParseForm()
      if err != nil {
        fmt.Printf("Couldn't parse form from request")
        http.Error(w, "", http.StatusUnauthorized)
      }
      token := r.Form[handler.Param]
      if token == nil || len(token) != 1 {
          fmt.Printf("Couldn't find param %v in request", handler.Param)
          http.Error(w, "", http.StatusUnauthorized)
      }
      auth, err := parseToken(token[0])
      if err != nil {
        fmt.Printf("Couldn't parse form token")
        http.Error(w, "", http.StatusUnauthorized)
      }

      if handler.isValid(auth) == false {
          fmt.Printf("Token %v is invalid", token)
          http.Error(w, "", http.StatusUnauthorized)
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


