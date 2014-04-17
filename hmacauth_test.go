package hmacauth

import (
  "testing"
  "net/http"
  "net/http/httptest"
)

var (
  h = &handler{Key: "testkey", Param: "token"}
)

func TestParseToken(t *testing.T) {
  message, err := parseToken("InRlc3Qi--3dd740af30f0453dd5220b56ba4fe57f48f892af")
  if err != nil {
    t.Fatalf("Error parsing token: %v", err)
  }

  if message.message != "InRlc3Qi" {
    t.Fatalf("parseToken parsed message %v", message.message)
  }

  if message.MAC != "3dd740af30f0453dd5220b56ba4fe57f48f892af" {
    t.Fatalf("parseToken parsed MAC %v", message.MAC)
  }

  if message.Decoded != "\"test\"" {
    t.Fatalf("parseToken decoded message as %v", message.Decoded)
  }
}

func TestExpectedHMACValue(t *testing.T) {
  message, err := parseToken("InRlc3Qi--3dd740af30f0453dd5220b56ba4fe57f48f892af")

  if err != nil {
    t.Fatalf("Error parsing token: %v", err)
  }

  if h.isValid(message) == false {
    t.Fatalf("handler cannot decrypt ActiveSupport::messageVerifier tokens")
  }
}

func TestAuthenticateWrapperWorks(t *testing.T) {
    handler := Authenticate("testkey", "token", func(response http.ResponseWriter, request *http.Request, token string) {
      response.Write([]byte(token))
    })

    recorder := httptest.NewRecorder()
    url := "http://example.com/echo?token=InRlc3Qi--3dd740af30f0453dd5220b56ba4fe57f48f892af"

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
      t.Fatalf("err in http request: %v", err)
    }

    handler(recorder, req)

    if body := recorder.Body.String(); body != "\"test\"" {
      t.Fatalf("unexpected body: %v", body)
    }
}

