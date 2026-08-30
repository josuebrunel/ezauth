package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
)

const webauthnChallengeTTL = 5 * time.Minute

var (
	ErrWebAuthnNotConfigured           = errors.New("webauthn is not configured; set EZAUTH_WEBAUTHN_RP_ID and EZAUTH_WEBAUTHN_RP_ORIGINS")
	ErrInvalidOrExpiredWebauthnSession = errors.New("invalid or expired webauthn session")
	ErrWebauthnCredentialNotFound      = errors.New("webauthn credential not found")
)

// webauthnUser adapts a models.User and its stored credentials to the webauthn.User
// interface required by the go-webauthn library.
type webauthnUser struct {
	user        *models.User
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u *webauthnUser) WebAuthnName() string                       { return u.user.Email }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.user.DisplayName() }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// webauthnCredentialID returns the lookup key used for a credential's raw ID, both
// when persisting it and when resolving an incoming assertion's raw ID back to a
// stored record. It must be applied consistently everywhere a raw credential ID is
// turned into a string key.
func webauthnCredentialID(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}

// webauthnLoadUser loads a user's persisted WebAuthn credentials and adapts them,
// along with the user, into the shape the go-webauthn library expects.
func (a *Auth) webauthnLoadUser(ctx context.Context, user *models.User) (*webauthnUser, error) {
	records, err := a.Repo.WebauthnCredentialListByUserID(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	creds := make([]webauthn.Credential, 0, len(records))
	for _, rec := range records {
		raw, err := json.Marshal(rec.Data)
		if err != nil {
			return nil, err
		}
		var cred webauthn.Credential
		if err := json.Unmarshal(raw, &cred); err != nil {
			return nil, err
		}
		creds = append(creds, cred)
	}
	return &webauthnUser{user: user, credentials: creds}, nil
}

// webauthnStoreSession persists a WebAuthn ceremony's SessionData (the challenge and
// associated parameters) as a short-lived WebauthnChallenge, returning the opaque
// key the caller must present to the matching Finish call. userID may be empty for
// a discoverable login challenge, where the authenticating user isn't known yet.
func (a *Auth) webauthnStoreSession(ctx context.Context, challengeType, userID string, session *webauthn.SessionData) (string, error) {
	sessionKey, err := a.generateRefreshToken()
	if err != nil {
		return "", err
	}

	raw, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	var data models.JSONMap
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", err
	}

	challenge := &models.WebauthnChallenge{
		SessionKey:    sessionKey,
		ChallengeType: challengeType,
		UserID:        userID,
		Data:          data,
		ExpiresAt:     time.Now().Add(webauthnChallengeTTL),
		CreatedAt:     time.Now(),
	}
	if _, err := a.Repo.WebauthnChallengeCreate(ctx, challenge); err != nil {
		return "", err
	}
	return sessionKey, nil
}

func (a *Auth) webauthnLoadSession(ctx context.Context, challengeType, sessionKey string) (*webauthn.SessionData, *models.WebauthnChallenge, error) {
	ch, err := a.Repo.WebauthnChallengeGetBySessionKey(ctx, sessionKey)
	if err != nil || ch.ChallengeType != challengeType {
		return nil, nil, ErrInvalidOrExpiredWebauthnSession
	}
	if time.Now().After(ch.ExpiresAt) {
		return nil, nil, ErrInvalidOrExpiredWebauthnSession
	}

	raw, err := json.Marshal(ch.Data)
	if err != nil {
		return nil, nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		return nil, nil, err
	}
	return &session, ch, nil
}

// WebauthnBeginRegistration begins a WebAuthn/passkey registration ceremony for an
// already-authenticated user, preferring (but not requiring) a discoverable
// credential so it can later be used for a usernameless login.
func (a *Auth) WebauthnBeginRegistration(ctx context.Context, user *models.User) (*protocol.CredentialCreation, string, error) {
	if a.WebAuthn == nil {
		return nil, "", ErrWebAuthnNotConfigured
	}

	waUser, err := a.webauthnLoadUser(ctx, user)
	if err != nil {
		return nil, "", err
	}

	creation, session, err := a.WebAuthn.BeginRegistration(waUser, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred))
	if err != nil {
		return nil, "", err
	}

	sessionKey, err := a.webauthnStoreSession(ctx, models.WebauthnChallengeTypeRegistration, user.ID, session)
	if err != nil {
		return nil, "", err
	}
	return creation, sessionKey, nil
}

// WebauthnFinishRegistration completes a registration ceremony started by
// WebauthnBeginRegistration, verifying r's body (the browser's
// PublicKeyCredential response) against the stored challenge and persisting the
// new credential under name (a user-supplied label, e.g. "YubiKey 5").
func (a *Auth) WebauthnFinishRegistration(ctx context.Context, user *models.User, sessionKey string, r *http.Request, name string) (*models.WebauthnCredential, error) {
	if a.WebAuthn == nil {
		return nil, ErrWebAuthnNotConfigured
	}

	session, tok, err := a.webauthnLoadSession(ctx, models.WebauthnChallengeTypeRegistration, sessionKey)
	if err != nil {
		return nil, err
	}
	if tok.UserID != user.ID {
		return nil, ErrInvalidOrExpiredWebauthnSession
	}

	waUser, err := a.webauthnLoadUser(ctx, user)
	if err != nil {
		return nil, err
	}

	cred, err := a.WebAuthn.FinishRegistration(waUser, *session, r)
	if err != nil {
		xlog.Debug("webauthn registration finish failed", "user_id", user.ID, "err", err)
		return nil, err
	}

	if err := a.Repo.WebauthnChallengeDelete(ctx, tok.ID); err != nil {
		xlog.Warn("failed to delete webauthn registration challenge", "challenge_id", tok.ID, "err", err)
	}

	dataMap, err := webauthnCredentialToJSONMap(cred)
	if err != nil {
		return nil, err
	}

	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}

	record := &models.WebauthnCredential{
		UserID:          user.ID,
		CredentialID:    webauthnCredentialID(cred.ID),
		PublicKey:       base64.StdEncoding.EncodeToString(cred.PublicKey),
		SignCount:       cred.Authenticator.SignCount,
		Transports:      strings.Join(transports, ","),
		AttestationType: cred.AttestationType,
		Name:            name,
		Data:            dataMap,
	}
	created, err := a.Repo.WebauthnCredentialCreate(ctx, record)
	if err != nil {
		return nil, err
	}
	xlog.Info("webauthn credential registered", "user_id", user.ID, "credential_record_id", created.ID)
	return created, nil
}

// WebauthnBeginLogin begins a discoverable (usernameless) WebAuthn login ceremony:
// the browser's platform UI lets the user pick which passkey to use, so no prior
// identifier (email/username) is required from the caller.
func (a *Auth) WebauthnBeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	if a.WebAuthn == nil {
		return nil, "", ErrWebAuthnNotConfigured
	}

	assertion, session, err := a.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", err
	}

	sessionKey, err := a.webauthnStoreSession(ctx, models.WebauthnChallengeTypeLogin, "", session)
	if err != nil {
		return nil, "", err
	}
	return assertion, sessionKey, nil
}

// WebauthnFinishLogin completes a login ceremony started by WebauthnBeginLogin,
// resolving which user is authenticating from the assertion's credential ID, then
// minting real session tokens on success.
func (a *Auth) WebauthnFinishLogin(ctx context.Context, sessionKey string, r *http.Request) (*models.User, *TokenResponse, error) {
	if a.WebAuthn == nil {
		return nil, nil, ErrWebAuthnNotConfigured
	}

	session, tok, err := a.webauthnLoadSession(ctx, models.WebauthnChallengeTypeLogin, sessionKey)
	if err != nil {
		return nil, nil, err
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		rec, err := a.Repo.WebauthnCredentialGetByCredentialID(ctx, webauthnCredentialID(rawID))
		if err != nil {
			return nil, ErrWebauthnCredentialNotFound
		}
		user, err := a.Repo.UserGetByID(ctx, rec.UserID)
		if err != nil {
			return nil, ErrWebauthnCredentialNotFound
		}
		return a.webauthnLoadUser(ctx, user)
	}

	waUser, cred, err := a.WebAuthn.FinishPasskeyLogin(handler, *session, r)
	if err != nil {
		xlog.Debug("webauthn login finish failed", "err", err)
		return nil, nil, err
	}
	resolved, ok := waUser.(*webauthnUser)
	if !ok || resolved.user == nil {
		return nil, nil, ErrWebauthnCredentialNotFound
	}
	user := resolved.user

	if err := a.Repo.WebauthnChallengeDelete(ctx, tok.ID); err != nil {
		xlog.Warn("failed to delete webauthn login challenge", "challenge_id", tok.ID, "err", err)
	}

	if rec, err := a.Repo.WebauthnCredentialGetByCredentialID(ctx, webauthnCredentialID(cred.ID)); err == nil {
		dataMap, err := webauthnCredentialToJSONMap(cred)
		if err == nil {
			now := time.Now()
			rec.Data = dataMap
			rec.SignCount = cred.Authenticator.SignCount
			rec.LastUsedAt = &now
			if _, err := a.Repo.WebauthnCredentialUpdate(ctx, rec); err != nil {
				xlog.Warn("failed to persist updated webauthn sign count", "credential_record_id", rec.ID, "err", err)
			}
		}
	}

	tokens, err := a.TokenCreate(ctx, user)
	if err != nil {
		return nil, nil, err
	}
	xlog.Info("webauthn login successful", "user_id", user.ID)
	return user, tokens, nil
}

// WebauthnCredentials lists the WebAuthn credentials registered for a user.
func (a *Auth) WebauthnCredentials(ctx context.Context, userID string) ([]*models.WebauthnCredential, error) {
	return a.Repo.WebauthnCredentialListByUserID(ctx, userID)
}

// WebauthnDeleteCredential removes one of user's registered WebAuthn credentials.
func (a *Auth) WebauthnDeleteCredential(ctx context.Context, user *models.User, credentialRecordID string) error {
	rec, err := a.Repo.WebauthnCredentialGetByID(ctx, credentialRecordID)
	if err != nil || rec.UserID != user.ID {
		return ErrWebauthnCredentialNotFound
	}
	return a.Repo.WebauthnCredentialDelete(ctx, rec.ID)
}

func webauthnCredentialToJSONMap(cred *webauthn.Credential) (models.JSONMap, error) {
	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	var m models.JSONMap
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
