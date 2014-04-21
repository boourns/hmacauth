package hmacauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"fmt"
)

var (
	h = &handler{Keys: []string{"testkey", "othertestkey"}, Param: "token"}
)

func TestParseToken(t *testing.T) {
	message, err := parseToken("InRlc3Qi--3dd740af30f0453dd5220b56ba4fe57f48f892af")
	if err != nil {
		t.Fatalf("Error parsing token: %v", err)
	}

	if message.Message != "InRlc3Qi" {
		t.Fatalf("parseToken parsed message %v", message.Message)
	}

	if message.MAC != "3dd740af30f0453dd5220b56ba4fe57f48f892af" {
		t.Fatalf("parseToken parsed MAC %v", message.MAC)
	}

	if message.Decoded != "\"test\"" {
		t.Fatalf("parseToken decoded message as %v", message.Decoded)
	}
}

func TestExpectedHMACValue(t *testing.T) {
	message, err := parseToken("WyIxNTg3MzYwMDEwIl0=--af40819c97a2a5d86d0e3222f5aada76ac3af397")

	if err != nil {
		t.Fatalf("Error parsing token: %v", err)
	}

	if h.isValid(message) == false {
		t.Fatalf("handler cannot decrypt ActiveSupport::messageVerifier tokens")
	}
}

func TestAlternateKeySucceeds(t *testing.T) {
	message, err := parseToken("WzE1MzUwMzc5MTNd--84081843e19ace8210ddb70ac27e401c44c01781")

	if err != nil {
		t.Fatalf("Error parsing token: %v", err)
	}

	if h.isValid(message) == false {
		t.Fatalf("handler cannot decrypt ActiveSupport::messageVerifier token for alternate key")
	}
}

func TestAuthenticateWrapperWorks(t *testing.T) {
	handler := Authenticate([]string{"testkey"}, "token", func(response http.ResponseWriter, request *http.Request, token []int64) {
		response.Write([]byte(fmt.Sprintf("%v", token)))
	})

	recorder := httptest.NewRecorder()
	url := "http://example.com/echo?token=WzE1ODczNjAwMTBd--de4702a95398d2305d52ddb0ec37b68ef80f92f6"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("err in http request: %v", err)
	}

	handler(recorder, req)

	if recorder.Code != 200 {
		t.Fatalf("HMAC authentication failed")
	}

	if body := recorder.Body.String(); body != "[1587360010]" {
		t.Fatalf("unexpected body: %v", body)
	}
}

func ConfirmFailURL(url string, t *testing.T) {
	handler := Authenticate([]string{"testkey"}, "token", func(response http.ResponseWriter, request *http.Request, token []int64) {
		t.Fatalf("HTTP request was not blocked in Authenticate()")
	})

	recorder := httptest.NewRecorder()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("err in http request: %v", err)
	}

	handler(recorder, req)

	if recorder.Code != 401 {
		t.Fatalf("HMAC authentication failed to block bad MAC")
	}
}

func TestAuthenticateBlocksWrongKey(t *testing.T) {
	ConfirmFailURL("http://example.com/echo?token=InRlc3Qi--4dd740af30f0453dd5220b56ba4fe57f48f892af", t)
}

func TestAuthenticateBlocksNoKeyWithSplit(t *testing.T) {
	ConfirmFailURL("http://example.com/echo?token=InRlc3Qi--", t)
}

func TestAuthenticateBlocksNoKeyWithoutSplit(t *testing.T) {
	ConfirmFailURL("http://example.com/echo?token=InRlc3Qi", t)
}

func TestAuthenticateBlocksNoKeyWithJustSplit(t *testing.T) {
	ConfirmFailURL("http://example.com/echo?token=--", t)
}

func TestAuthenticateBlocksNoKey(t *testing.T) {
	ConfirmFailURL("http://example.com/echo", t)
}

func TestAuthenticateBlocksExpiredTokens(t *testing.T) {
	ConfirmFailURL("http://example.com/echo?token=WzEzMzUwMzc5MTNd--9c277685955744ab4ebd62309584c72edb635dbf", t)
}

