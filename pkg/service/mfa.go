package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
	"github.com/pquerna/otp/totp"
)

const (
	mfaPreAuthTokenTTL   = 5 * time.Minute
	mfaRecoveryCodeCount = 10
)

var (
	ErrMFAAlreadyEnabled        = errors.New("mfa is already enabled")
	ErrMFANotEnabled            = errors.New("mfa is not enabled for this account")
	ErrMFAEnrollmentNotStarted  = errors.New("mfa enrollment has not been started; call MFAEnroll first")
	ErrInvalidMFACode           = errors.New("invalid mfa code")
	ErrInvalidOrExpiredMFAToken = errors.New("invalid or expired mfa token")
)

// MFAEnrollResponse carries the newly generated TOTP secret and its otpauth:// URL
// (for rendering as a QR code) so the user can add it to an authenticator app.
type MFAEnrollResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

// LoginResponse is returned after a successful password check. If the account has
// MFA enabled, TokenResponse is nil and MFARequired/MFAToken are set instead; the
// caller must complete MFALoginVerify with that token and a TOTP/recovery code
// before receiving real session tokens.
type LoginResponse struct {
	*TokenResponse
	MFARequired bool   `json:"mfa_required,omitempty"`
	MFAToken    string `json:"mfa_token,omitempty"`
}

// CompleteBasicLogin finishes a password-authenticated login. If the user has MFA
// enabled and deviceToken isn't a trusted device for this user (see TrustDevice),
// it issues a short-lived pre-auth token instead of a full session, which must be
// exchanged via MFALoginVerify. Otherwise it mints session tokens directly.
func (a *Auth) CompleteBasicLogin(ctx context.Context, user *models.User, deviceToken string) (*LoginResponse, error) {
	if user.MfaEnabled && !a.IsTrustedDevice(ctx, user, deviceToken) {
		mfaToken, err := a.mfaIssuePreAuthToken(ctx, user)
		if err != nil {
			xlog.Error("failed to issue mfa pre-auth token", "user_id", user.ID, "err", err)
			return nil, err
		}
		xlog.Info("mfa step-up required", "user_id", user.ID)
		return &LoginResponse{MFARequired: true, MFAToken: mfaToken}, nil
	}

	tokens, err := a.TokenCreate(ctx, user)
	if err != nil {
		return nil, err
	}
	return &LoginResponse{TokenResponse: tokens}, nil
}

func (a *Auth) mfaIssuePreAuthToken(ctx context.Context, user *models.User) (string, error) {
	tokenValue, err := a.generateRefreshToken()
	if err != nil {
		return "", err
	}

	token := &models.Token{
		UserID:    user.ID,
		Token:     tokenValue,
		TokenType: models.TokenTypeMFAPreAuth,
		ExpiresAt: time.Now().Add(mfaPreAuthTokenTTL),
		CreatedAt: time.Now(),
		Metadata:  models.JSONMap{},
	}

	if _, err := a.Repo.TokenCreate(ctx, token); err != nil {
		return "", err
	}
	return tokenValue, nil
}

// MFAEnroll begins TOTP enrollment for user, generating and persisting a new secret.
// MFA is not enabled yet — the enrollment must be confirmed via MFAConfirm with a
// valid code from the authenticator app before it takes effect.
func (a *Auth) MFAEnroll(ctx context.Context, user *models.User) (*MFAEnrollResponse, error) {
	if user.MfaEnabled {
		return nil, ErrMFAAlreadyEnabled
	}

	issuer := a.Cfg.MFAIssuer
	if issuer == "" {
		issuer = "EzAuth"
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user.Email,
	})
	if err != nil {
		xlog.Error("failed to generate mfa secret", "user_id", user.ID, "err", err)
		return nil, err
	}

	secret := key.Secret()
	user.MfaSecret = &secret
	if _, err := a.Repo.UserUpdate(ctx, user); err != nil {
		xlog.Error("failed to persist mfa enrollment secret", "user_id", user.ID, "err", err)
		return nil, err
	}

	xlog.Info("mfa enrollment started", "user_id", user.ID)
	return &MFAEnrollResponse{Secret: secret, OTPAuthURL: key.URL()}, nil
}

// MFAConfirm completes TOTP enrollment: it validates code against the pending
// secret from MFAEnroll, enables MFA, and returns a set of one-time recovery codes.
// The plaintext codes are only ever returned here — only their hashes are persisted.
func (a *Auth) MFAConfirm(ctx context.Context, user *models.User, code string) ([]string, error) {
	if user.MfaEnabled {
		return nil, ErrMFAAlreadyEnabled
	}
	if user.MfaSecret == nil || *user.MfaSecret == "" {
		return nil, ErrMFAEnrollmentNotStarted
	}
	if !totp.Validate(code, *user.MfaSecret) {
		xlog.Debug("mfa enrollment confirmation failed: invalid code", "user_id", user.ID)
		return nil, ErrInvalidMFACode
	}

	user.MfaEnabled = true
	if _, err := a.Repo.UserUpdate(ctx, user); err != nil {
		xlog.Error("failed to enable mfa", "user_id", user.ID, "err", err)
		return nil, err
	}

	codes, err := a.mfaGenerateRecoveryCodes(ctx, user)
	if err != nil {
		xlog.Error("failed to generate mfa recovery codes", "user_id", user.ID, "err", err)
		return nil, err
	}

	xlog.Info("mfa enabled", "user_id", user.ID)
	return codes, nil
}

// MFADisable turns off MFA for user after validating a current TOTP or recovery
// code, clearing the secret and revoking any unused recovery codes.
func (a *Auth) MFADisable(ctx context.Context, user *models.User, code string) error {
	if !user.MfaEnabled {
		return ErrMFANotEnabled
	}

	if !a.mfaValidateAnyCode(ctx, user, code) {
		xlog.Debug("mfa disable failed: invalid code", "user_id", user.ID)
		return ErrInvalidMFACode
	}

	user.MfaEnabled = false
	empty := ""
	user.MfaSecret = &empty
	if _, err := a.Repo.UserUpdate(ctx, user); err != nil {
		xlog.Error("failed to disable mfa", "user_id", user.ID, "err", err)
		return err
	}

	if err := a.Repo.TokenRevokeAllByUserID(ctx, user.ID); err != nil {
		xlog.Warn("failed to revoke recovery/preauth tokens after mfa disable", "user_id", user.ID, "err", err)
	}

	xlog.Info("mfa disabled", "user_id", user.ID)
	return nil
}

// MFALoginVerify completes a step-up login: it validates the pre-auth token issued
// by CompleteBasicLogin and a TOTP or recovery code, then mints real session tokens.
// When rememberDevice is true, it also issues a trusted-device token (see
// TrustDevice) so future logins from the same device can skip this step-up for
// Cfg.TrustedDevice.TTL; deviceToken is empty when rememberDevice is false.
func (a *Auth) MFALoginVerify(ctx context.Context, mfaToken, code string, rememberDevice bool) (user *models.User, tokens *TokenResponse, deviceToken string, err error) {
	token, err := a.Repo.TokenGetByToken(ctx, mfaToken)
	if err != nil || token.TokenType != models.TokenTypeMFAPreAuth {
		xlog.Debug("mfa login verify failed: token not found or wrong type", "err", err)
		return nil, nil, "", ErrInvalidOrExpiredMFAToken
	}

	if token.Revoked || time.Now().After(token.ExpiresAt) {
		xlog.Debug("mfa login verify failed: token expired or revoked", "token_id", token.ID)
		return nil, nil, "", ErrInvalidOrExpiredMFAToken
	}

	user, err = a.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		return nil, nil, "", err
	}

	if !a.mfaValidateAnyCode(ctx, user, code) {
		xlog.Debug("mfa login verify failed: invalid code", "user_id", user.ID)
		return nil, nil, "", ErrInvalidMFACode
	}

	if err := a.Repo.TokenRevoke(ctx, token.ID); err != nil {
		xlog.Error("failed to revoke mfa pre-auth token", "token_id", token.ID, "err", err)
		return nil, nil, "", err
	}

	if rememberDevice {
		deviceToken, err = a.TrustDevice(ctx, user, "")
		if err != nil {
			xlog.Warn("failed to issue trusted device token", "user_id", user.ID, "err", err)
			deviceToken = ""
		}
	}

	tokens, err = a.TokenCreate(ctx, user)
	if err != nil {
		return nil, nil, "", err
	}
	xlog.Info("mfa step-up completed", "user_id", user.ID)
	return user, tokens, deviceToken, nil
}

// mfaValidateAnyCode accepts either a live TOTP code or an unused recovery code.
func (a *Auth) mfaValidateAnyCode(ctx context.Context, user *models.User, code string) bool {
	if user.MfaSecret != nil && *user.MfaSecret != "" && totp.Validate(code, *user.MfaSecret) {
		return true
	}
	return a.mfaConsumeRecoveryCode(ctx, user, code)
}

func mfaHashRecoveryCode(userID, code string) string {
	sum := sha256.Sum256([]byte(userID + ":" + code))
	return hex.EncodeToString(sum[:])
}

func (a *Auth) mfaGenerateRecoveryCodes(ctx context.Context, user *models.User) ([]string, error) {
	// Any previously issued, still-unused recovery codes are invalidated by
	// re-enrollment so old codes can't be replayed against a new secret.
	if err := a.Repo.TokenRevokeAllByUserID(ctx, user.ID); err != nil {
		xlog.Warn("failed to revoke old mfa tokens before issuing new recovery codes", "user_id", user.ID, "err", err)
	}

	codes := make([]string, 0, mfaRecoveryCodeCount)
	for i := 0; i < mfaRecoveryCodeCount; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)

		token := &models.Token{
			UserID:    user.ID,
			Token:     mfaHashRecoveryCode(user.ID, code),
			TokenType: models.TokenTypeMFARecovery,
			ExpiresAt: time.Now().AddDate(10, 0, 0),
			CreatedAt: time.Now(),
			Metadata:  models.JSONMap{},
		}
		if _, err := a.Repo.TokenCreate(ctx, token); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

func (a *Auth) mfaConsumeRecoveryCode(ctx context.Context, user *models.User, code string) bool {
	if code == "" {
		return false
	}
	hashed := mfaHashRecoveryCode(user.ID, code)
	token, err := a.Repo.TokenGetByToken(ctx, hashed)
	if err != nil {
		return false
	}
	if token.TokenType != models.TokenTypeMFARecovery || token.UserID != user.ID {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(token.Token), []byte(hashed)) != 1 {
		return false
	}
	if token.Revoked {
		return false
	}
	if err := a.Repo.TokenRevoke(ctx, token.ID); err != nil {
		xlog.Error("failed to revoke used mfa recovery code", "token_id", token.ID, "err", err)
		return false
	}
	xlog.Info("mfa recovery code used", "user_id", user.ID)
	return true
}

func generateRecoveryCode() (string, error) {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", hex.EncodeToString(b[:2]), hex.EncodeToString(b[2:])), nil
}
