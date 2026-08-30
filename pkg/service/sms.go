package service

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/gopkg/xlog"
)

// SMSSender defines the interface for sending SMS messages.
// Implement this to plug in an SMS provider other than Twilio.
type SMSSender interface {
	Send(to string, body string) error
}

// TwilioSMSSender implements SMSSender using Twilio's REST API.
type TwilioSMSSender struct {
	cfg    config.SMS
	client *http.Client
}

// NewTwilioSMSSender creates a new TwilioSMSSender.
func NewTwilioSMSSender(cfg config.SMS) *TwilioSMSSender {
	return &TwilioSMSSender{cfg: cfg, client: &http.Client{}}
}

// Send sends an SMS via Twilio's Messages REST API.
func (s *TwilioSMSSender) Send(to string, body string) error {
	// Defense in depth: `to` and `body` are sent as form-encoded values, but
	// guard against CR/LF the same way the mailer does, in case a caller ever
	// bypasses upstream validation.
	if strings.ContainsAny(to, "\r\n") {
		err := errors.New("sms recipient injection attempt blocked")
		xlog.Error("refusing to send sms with CR/LF in recipient value", "error", err)
		return err
	}

	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", s.cfg.AccountSID)
	form := url.Values{
		"To":   {to},
		"From": {s.cfg.From},
		"Body": {body},
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.cfg.AccountSID, s.cfg.AuthToken)

	resp, err := s.client.Do(req)
	if err != nil {
		xlog.Error("failed to send sms", "error", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		err := fmt.Errorf("sms provider returned status %s", resp.Status)
		xlog.Error("failed to send sms", "error", err)
		return err
	}
	return nil
}

// MockSMSSender implements SMSSender for testing purposes and as the fallback
// when no SMS provider is configured.
type MockSMSSender struct {
	SentMessages []map[string]string
}

// NewMockSMSSender creates a new MockSMSSender.
func NewMockSMSSender() *MockSMSSender {
	return &MockSMSSender{SentMessages: make([]map[string]string, 0)}
}

func (s *MockSMSSender) Send(to string, body string) error {
	s.SentMessages = append(s.SentMessages, map[string]string{"to": to, "body": body})
	xlog.Debug("mock sms sent", "to", to)
	return nil
}

// SMSTemplateData contains variables available in SMS templates.
type SMSTemplateData struct {
	Code  string // The one-time code
	Phone string // The recipient's phone number
}
