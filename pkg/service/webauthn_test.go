package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

const (
	testWebauthnRPID   = "example.com"
	testWebauthnOrigin = "https://example.com"
)

func setupWebauthnTestDB(t *testing.T, withWebauthn bool) *Auth {
	dialect, dsn := util.GetTestDBConfig("webauthn_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
		Hashing:   config.Hashing{BcryptCost: 4}, // bcrypt.MinCost: correctness doesn't need real cost-14 hashing
	}
	if withWebauthn {
		cfg.WebAuthn = config.WebAuthn{
			RPID:          testWebauthnRPID,
			RPDisplayName: "EzAuth Test",
			RPOrigins:     testWebauthnOrigin,
		}
	}

	auth, err := NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	if err := ensureMigrated(auth.Repo.DB(), dialect, dsn); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return auth
}

func webauthnTestUser(t *testing.T, auth *Auth, ctx context.Context) *models.User {
	t.Helper()
	user, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:        util.UniqueEmail("webauthnuser"),
		PasswordHash: "some-hash",
		Provider:     "local",
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	return user
}

func TestWebauthnNotConfigured(t *testing.T) {
	auth := setupWebauthnTestDB(t, false)
	ctx := context.Background()
	user := webauthnTestUser(t, auth, ctx)

	if _, _, err := auth.WebauthnBeginRegistration(ctx, user); err != ErrWebAuthnNotConfigured {
		t.Fatalf("expected ErrWebAuthnNotConfigured, got %v", err)
	}
	if _, _, err := auth.WebauthnBeginLogin(ctx); err != ErrWebAuthnNotConfigured {
		t.Fatalf("expected ErrWebAuthnNotConfigured, got %v", err)
	}
}

func TestWebauthnRegisterAndLoginEndToEnd(t *testing.T) {
	auth := setupWebauthnTestDB(t, true)
	ctx := context.Background()
	user := webauthnTestUser(t, auth, ctx)
	authenticator := newVirtualAuthenticator(t)

	var credentialRecordID string
	t.Run("register", func(t *testing.T) {
		creation, sessionKey, err := auth.WebauthnBeginRegistration(ctx, user)
		if err != nil {
			t.Fatalf("WebauthnBeginRegistration failed: %v", err)
		}
		if sessionKey == "" || creation.Response.Challenge == nil {
			t.Fatalf("expected creation options and session key, got %+v / %q", creation, sessionKey)
		}

		challenge := creation.Response.Challenge.String()
		req := authenticator.registrationRequest(t, challenge)

		cred, err := auth.WebauthnFinishRegistration(ctx, user, sessionKey, req, "Test Authenticator")
		if err != nil {
			t.Fatalf("WebauthnFinishRegistration failed: %v", err)
		}
		if cred.UserID != user.ID || cred.Name != "Test Authenticator" || cred.SignCount != 0 {
			t.Fatalf("unexpected credential record: %+v", cred)
		}
		credentialRecordID = cred.ID

		// The registration challenge must be single-use.
		if _, err := auth.WebauthnFinishRegistration(ctx, user, sessionKey, authenticator.registrationRequest(t, challenge), "again"); err == nil {
			t.Fatal("expected reused registration session to be rejected")
		}
	})

	t.Run("list credentials", func(t *testing.T) {
		creds, err := auth.WebauthnCredentials(ctx, user.ID)
		if err != nil {
			t.Fatalf("WebauthnCredentials failed: %v", err)
		}
		if len(creds) != 1 || creds[0].ID != credentialRecordID {
			t.Fatalf("expected exactly the registered credential, got %+v", creds)
		}
	})

	var loginTokens *TokenResponse
	t.Run("login", func(t *testing.T) {
		assertion, sessionKey, err := auth.WebauthnBeginLogin(ctx)
		if err != nil {
			t.Fatalf("WebauthnBeginLogin failed: %v", err)
		}
		if sessionKey == "" {
			t.Fatal("expected a session key")
		}

		challenge := assertion.Response.Challenge.String()
		req := authenticator.assertionRequest(t, challenge, []byte(user.ID))

		gotUser, tokens, err := auth.WebauthnFinishLogin(ctx, sessionKey, req)
		if err != nil {
			t.Fatalf("WebauthnFinishLogin failed: %v", err)
		}
		if gotUser.ID != user.ID || tokens.AccessToken == "" {
			t.Fatalf("unexpected login result: user=%+v tokens=%+v", gotUser, tokens)
		}
		loginTokens = tokens

		// The login challenge must be single-use.
		if _, _, err := auth.WebauthnFinishLogin(ctx, sessionKey, authenticator.assertionRequest(t, challenge, []byte(user.ID))); err == nil {
			t.Fatal("expected reused login session to be rejected")
		}
	})

	t.Run("sign count persisted after login", func(t *testing.T) {
		creds, err := auth.WebauthnCredentials(ctx, user.ID)
		if err != nil {
			t.Fatalf("WebauthnCredentials failed: %v", err)
		}
		if len(creds) != 1 || creds[0].SignCount != 1 {
			t.Fatalf("expected sign count 1 after one login, got %+v", creds)
		}
		if creds[0].LastUsedAt == nil {
			t.Fatal("expected last_used_at to be set after login")
		}
	})

	if loginTokens == nil {
		t.Fatal("login subtest did not run")
	}

	t.Run("delete credential", func(t *testing.T) {
		if err := auth.WebauthnDeleteCredential(ctx, user, credentialRecordID); err != nil {
			t.Fatalf("WebauthnDeleteCredential failed: %v", err)
		}
		creds, err := auth.WebauthnCredentials(ctx, user.ID)
		if err != nil {
			t.Fatalf("WebauthnCredentials failed: %v", err)
		}
		if len(creds) != 0 {
			t.Fatalf("expected no credentials after delete, got %+v", creds)
		}
	})

	t.Run("delete rejects another user's credential", func(t *testing.T) {
		other := webauthnTestUser(t, auth, ctx)
		authenticator2 := newVirtualAuthenticator(t)
		creation, sessionKey, err := auth.WebauthnBeginRegistration(ctx, other)
		if err != nil {
			t.Fatalf("WebauthnBeginRegistration failed: %v", err)
		}
		challenge := creation.Response.Challenge.String()
		cred, err := auth.WebauthnFinishRegistration(ctx, other, sessionKey, authenticator2.registrationRequest(t, challenge), "other")
		if err != nil {
			t.Fatalf("WebauthnFinishRegistration failed: %v", err)
		}

		if err := auth.WebauthnDeleteCredential(ctx, user, cred.ID); err != ErrWebauthnCredentialNotFound {
			t.Fatalf("expected ErrWebauthnCredentialNotFound, got %v", err)
		}
	})
}

// virtualAuthenticator simulates a single WebAuthn authenticator (e.g. a
// platform passkey) backed by an in-memory ES256/P-256 keypair, so registration
// and login ceremonies can be exercised end-to-end without a real browser.
type virtualAuthenticator struct {
	t            *testing.T
	private      *ecdsa.PrivateKey
	credentialID []byte
	signCount    uint32
}

func newVirtualAuthenticator(t *testing.T) *virtualAuthenticator {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	credentialID := make([]byte, 16)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("failed to generate credential id: %v", err)
	}
	return &virtualAuthenticator{t: t, private: private, credentialID: credentialID}
}

func (v *virtualAuthenticator) cosePublicKey() []byte {
	v.t.Helper()
	data, err := webauthncbor.Marshal(map[int]any{
		1:  int64(webauthncose.EllipticKey),
		3:  int64(webauthncose.AlgES256),
		-1: int64(webauthncose.P256),
		-2: v.private.PublicKey.X.FillBytes(make([]byte, 32)),
		-3: v.private.PublicKey.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		v.t.Fatalf("failed to marshal cose public key: %v", err)
	}
	return data
}

func (v *virtualAuthenticator) authenticatorData(flags protocol.AuthenticatorFlags, includeAttestedData bool) []byte {
	v.t.Helper()
	rpIDHash := sha256.Sum256([]byte(testWebauthnRPID))

	data := make([]byte, 0, 37)
	data = append(data, rpIDHash[:]...)
	data = append(data, byte(flags))
	data = binary.BigEndian.AppendUint32(data, v.signCount)

	if includeAttestedData {
		attested := make([]byte, 16) // AAGUID, all zero for a test authenticator.
		attested = binary.BigEndian.AppendUint16(attested, uint16(len(v.credentialID)))
		attested = append(attested, v.credentialID...)
		attested = append(attested, v.cosePublicKey()...)
		data = append(data, attested...)
	}
	return data
}

func (v *virtualAuthenticator) sign(authData, clientDataJSON []byte) []byte {
	v.t.Helper()
	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, v.private, digest[:])
	if err != nil {
		v.t.Fatalf("failed to sign: %v", err)
	}
	return sig
}

func clientDataJSON(t *testing.T, ceremony protocol.CeremonyType, challenge string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"type":      string(ceremony),
		"challenge": challenge,
		"origin":    testWebauthnOrigin,
	})
	if err != nil {
		t.Fatalf("failed to marshal client data json: %v", err)
	}
	return data
}

// registrationRequest builds an *http.Request whose body is the JSON a browser
// would send back from navigator.credentials.create() for this authenticator.
func (v *virtualAuthenticator) registrationRequest(t *testing.T, challenge string) *http.Request {
	t.Helper()
	authData := v.authenticatorData(protocol.FlagUserPresent|protocol.FlagUserVerified|protocol.FlagAttestedCredentialData, true)
	cdj := clientDataJSON(t, protocol.CreateCeremony, challenge)

	attestationObject, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		t.Fatalf("failed to marshal attestation object: %v", err)
	}

	id := base64.RawURLEncoding.EncodeToString(v.credentialID)
	body, err := json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cdj),
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal registration body: %v", err)
	}

	return httpPostJSON(body)
}

// assertionRequest builds an *http.Request whose body is the JSON a browser
// would send back from navigator.credentials.get() for this authenticator.
func (v *virtualAuthenticator) assertionRequest(t *testing.T, challenge string, userHandle []byte) *http.Request {
	t.Helper()
	v.signCount++
	authData := v.authenticatorData(protocol.FlagUserPresent|protocol.FlagUserVerified, false)
	cdj := clientDataJSON(t, protocol.AssertCeremony, challenge)
	sig := v.sign(authData, cdj)

	id := base64.RawURLEncoding.EncodeToString(v.credentialID)
	body, err := json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cdj),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
			"userHandle":        base64.RawURLEncoding.EncodeToString(userHandle),
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal assertion body: %v", err)
	}

	return httpPostJSON(body)
}

func httpPostJSON(body []byte) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "https://example.com/webauthn/finish", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}
