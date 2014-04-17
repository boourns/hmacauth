package hmacauth

import (
  "testing"
)

var (
  handler = &Handler{Key: "testkey", Param: "token"}
)

func TestParseToken(t *testing.T) {
  message, err := parseToken([]byte("InRlc3Qi--3dd740af30f0453dd5220b56ba4fe57f48f892af"))
  if err != nil {
    t.Fatalf("Error parsing token: %v", err)
  }

  if message.Message != "InRlc3Qi" {
    t.Fatalf("parseToken parsed message %v", message.Message)
  }

  if message.MAC != "3dd740af30f0453dd5220b56ba4fe57f48f892af" {
    t.Fatalf("parseToken parsed MAC %v", message.MAC)
  }

  if message.Deserialized != "\"test\"" {
    t.Fatalf("parseToken deserialized message as %v", message.Deserialized)
  }
}

func TestExpectedHMACValue(t *testing.T) {
  message, err := parseToken([]byte("InRlc3Qi--3dd740af30f0453dd5220b56ba4fe57f48f892af"))

  if err != nil {
    t.Fatalf("Error parsing token: %v", err)
  }

  if handler.isValid(message) == false {
    t.Fatalf("handler cannot decrypt ActiveSupport::MessageVerifier tokens")
  }
}

