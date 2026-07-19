package config

import (
	"os"
	"testing"
)

func TestLoadCustomOAuth2Providers_Success(t *testing.T) {
	// Setup environment variables
	os.Setenv("EZAUTH_OAUTH2_PROVIDERS", "okta, custom_manual")
	os.Setenv("EZAUTH_OAUTH2_OKTA_CLIENT_ID", "okta-id")
	os.Setenv("EZAUTH_OAUTH2_OKTA_CLIENT_SECRET", "okta-secret")
	os.Setenv("EZAUTH_OAUTH2_OKTA_REDIRECT_URL", "http://localhost/okta/callback")
	os.Setenv("EZAUTH_OAUTH2_OKTA_SCOPES", "openid,email")
	os.Setenv("EZAUTH_OAUTH2_OKTA_ISSUER_URL", "https://issuer.com")

	os.Setenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_CLIENT_ID", "manual-id")
	os.Setenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_CLIENT_SECRET", "manual-secret")
	os.Setenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_REDIRECT_URL", "http://localhost/manual/callback")
	os.Setenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_SCOPES", "profile,email")
	os.Setenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_AUTH_URL", "https://auth.com")
	os.Setenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_TOKEN_URL", "https://token.com")
	os.Setenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_USERINFO_URL", "https://userinfo.com")
	os.Setenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_ID_FIELD", "sub")
	os.Setenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_EMAIL_FIELD", "mail")

	defer func() {
		os.Unsetenv("EZAUTH_OAUTH2_PROVIDERS")
		os.Unsetenv("EZAUTH_OAUTH2_OKTA_CLIENT_ID")
		os.Unsetenv("EZAUTH_OAUTH2_OKTA_CLIENT_SECRET")
		os.Unsetenv("EZAUTH_OAUTH2_OKTA_REDIRECT_URL")
		os.Unsetenv("EZAUTH_OAUTH2_OKTA_SCOPES")
		os.Unsetenv("EZAUTH_OAUTH2_OKTA_ISSUER_URL")

		os.Unsetenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_CLIENT_ID")
		os.Unsetenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_CLIENT_SECRET")
		os.Unsetenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_REDIRECT_URL")
		os.Unsetenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_SCOPES")
		os.Unsetenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_AUTH_URL")
		os.Unsetenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_TOKEN_URL")
		os.Unsetenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_USERINFO_URL")
		os.Unsetenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_ID_FIELD")
		os.Unsetenv("EZAUTH_OAUTH2_CUSTOM_MANUAL_EMAIL_FIELD")
	}()

	providers, err := LoadCustomOAuth2Providers()
	if err != nil {
		t.Fatalf("expected no error loading custom providers, got: %v", err)
	}

	if len(providers) != 2 {
		t.Fatalf("expected 2 custom providers, got: %d", len(providers))
	}

	// Verify Okta
	okta := providers[0]
	if okta.Name != "okta" {
		t.Errorf("expected provider name 'okta', got: %s", okta.Name)
	}
	if okta.ClientID != "okta-id" || okta.ClientSecret != "okta-secret" || okta.RedirectURL != "http://localhost/okta/callback" {
		t.Error("incorrect core config for okta")
	}
	if len(okta.Scopes) != 2 || okta.Scopes[0] != "openid" || okta.Scopes[1] != "email" {
		t.Errorf("incorrect scopes for okta: %v", okta.Scopes)
	}
	if okta.IssuerURL != "https://issuer.com" {
		t.Errorf("expected issuer URL 'https://issuer.com', got: %s", okta.IssuerURL)
	}

	// Verify Custom Manual
	manual := providers[1]
	if manual.Name != "custom_manual" {
		t.Errorf("expected provider name 'custom_manual', got: %s", manual.Name)
	}
	if manual.ClientID != "manual-id" || manual.ClientSecret != "manual-secret" || manual.RedirectURL != "http://localhost/manual/callback" {
		t.Error("incorrect core config for manual")
	}
	if len(manual.Scopes) != 2 || manual.Scopes[0] != "profile" || manual.Scopes[1] != "email" {
		t.Errorf("incorrect scopes for manual: %v", manual.Scopes)
	}
	if manual.IssuerURL != "" {
		t.Errorf("expected empty issuer URL, got: %s", manual.IssuerURL)
	}
	if manual.AuthURL != "https://auth.com" || manual.TokenURL != "https://token.com" || manual.UserinfoURL != "https://userinfo.com" {
		t.Error("incorrect manual URL endpoints")
	}
	if manual.IDField != "sub" || manual.EmailField != "mail" {
		t.Errorf("incorrect fields: id=%s, email=%s", manual.IDField, manual.EmailField)
	}
}

func TestLoadCustomOAuth2Providers_MissingRequiredField(t *testing.T) {
	os.Setenv("EZAUTH_OAUTH2_PROVIDERS", "missing_secret")
	os.Setenv("EZAUTH_OAUTH2_MISSING_SECRET_CLIENT_ID", "some-id")
	// client secret is missing

	defer func() {
		os.Unsetenv("EZAUTH_OAUTH2_PROVIDERS")
		os.Unsetenv("EZAUTH_OAUTH2_MISSING_SECRET_CLIENT_ID")
	}()

	_, err := LoadCustomOAuth2Providers()
	if err == nil {
		t.Error("expected error due to missing client secret, got nil")
	}
}

func TestLoadCustomOAuth2Providers_MissingManualEndpoint(t *testing.T) {
	os.Setenv("EZAUTH_OAUTH2_PROVIDERS", "missing_endpoint")
	os.Setenv("EZAUTH_OAUTH2_MISSING_ENDPOINT_CLIENT_ID", "some-id")
	os.Setenv("EZAUTH_OAUTH2_MISSING_ENDPOINT_CLIENT_SECRET", "some-secret")
	os.Setenv("EZAUTH_OAUTH2_MISSING_ENDPOINT_REDIRECT_URL", "http://localhost/callback")
	// no issuer URL AND no auth/token/userinfo URLs

	defer func() {
		os.Unsetenv("EZAUTH_OAUTH2_PROVIDERS")
		os.Unsetenv("EZAUTH_OAUTH2_MISSING_ENDPOINT_CLIENT_ID")
		os.Unsetenv("EZAUTH_OAUTH2_MISSING_ENDPOINT_CLIENT_SECRET")
		os.Unsetenv("EZAUTH_OAUTH2_MISSING_ENDPOINT_REDIRECT_URL")
	}()

	_, err := LoadCustomOAuth2Providers()
	if err == nil {
		t.Error("expected error due to missing manual endpoints/issuer, got nil")
	}
}
