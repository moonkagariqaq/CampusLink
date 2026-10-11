package main

import (
	"esurfing/cipher"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type plainTestCipher struct{}

func (plainTestCipher) Encrypt(s string) string { return s }
func (plainTestCipher) Decrypt(s string) string { return s }

func TestHeartbeatRejectsInvalidAcknowledgement(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"success", "<response><response-code>0</response-code><keep-retry>45</keep-retry></response>", true},
		{"native interval", "<response><interval>45</interval></response>", true},
		{"rejected", "<response><response-code>200</response-code></response>", false},
		{"html instead of ack", "<html>login required</html>", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) }))
			defer server.Close()
			states := NewStates()
			states.RefreshStates()
			session := NewSession()
			session.cipher = plainTestCipher{}
			session.initialized = true
			client := NewClient(Options{}, states, session)
			client.keepURL = server.URL
			err := client.heartbeat("test-ticket")
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if tc.valid && client.keepRetry != "45" {
				t.Fatal("server heartbeat interval not applied")
			}
		})
	}
}
func TestMalformedWindowsModuleRejected(t *testing.T) {
	for _, data := range [][]byte{nil, make([]byte, 16), {0, 0, 0, 255}, append([]byte{0, 0, 0, 0, 0}, make([]byte, 128)...)} {
		if _, err := cipher.NewWindowsZSMCipher(data); err == nil {
			t.Fatal("invalid algorithm container accepted")
		}
	}
}
