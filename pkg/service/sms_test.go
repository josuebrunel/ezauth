package service

import (
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
)

// TestNewTwilioSMSSender_ClientHasTimeout proves the Twilio HTTP client has
// a bounded timeout -- the zero-value http.Client{} it used to be
// constructed with waits forever on a stalled connection/response.
func TestNewTwilioSMSSender_ClientHasTimeout(t *testing.T) {
	s := NewTwilioSMSSender(config.SMS{AccountSID: "AC_test", AuthToken: "test", From: "+15550000000"})
	if s.client.Timeout <= 0 {
		t.Fatalf("expected a positive client timeout, got %v", s.client.Timeout)
	}
}
