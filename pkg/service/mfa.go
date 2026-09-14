package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/josuebrunel/gopkg/xlog"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
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
		Token:     util.HashToken(tokenValue),
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

	if a.Cfg.AccountLockout.Enabled {
		var err error
		if user, err = a.checkAccountActive(ctx, user); err != nil {
			xlog.Debug("mfa confirm failed: account locked", "user_id", user.ID, "err", err)
			return nil, err
		}
	}

	if !totp.Validate(code, *user.MfaSecret) {
		xlog.Debug("mfa enrollment confirmation failed: invalid code", "user_id", user.ID)
		if a.Cfg.AccountLockout.Enabled {
			a.recordFailedLogin(ctx, user)
		}
		return nil, ErrInvalidMFACode
	}

	user.MfaEnabled = true
	if _, err := a.Repo.UserSetMFAEnabled(ctx, user.ID, true); err != nil {
		xlog.Error("failed to enable mfa", "user_id", user.ID, "err", err)
		return nil, err
	}

	codes, err := a.mfaGenerateRecoveryCodes(ctx, user)
	if err != nil {
		xlog.Error("failed to generate mfa recovery codes", "user_id", user.ID, "err", err)
		return nil, err
	}

	if user.FailedLoginAttempts > 0 {
		if _, err := a.Repo.UserSetLockoutState(ctx, user.ID, 0, nil, true); err != nil {
			xlog.Warn("failed to reset failed login attempt counter after mfa confirm success", "user_id", user.ID, "err", err)
		}
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

	if a.Cfg.AccountLockout.Enabled {
		var err error
		if user, err = a.checkAccountActive(ctx, user); err != nil {
			xlog.Debug("mfa disable failed: account locked", "user_id", user.ID, "err", err)
			return err
		}
	}

	if !a.mfaValidateAnyCode(ctx, user, code) {
		xlog.Debug("mfa disable failed: invalid code", "user_id", user.ID)
		if a.Cfg.AccountLockout.Enabled {
			a.recordFailedLogin(ctx, user)
		}
		return ErrInvalidMFACode
	}

	if user.FailedLoginAttempts > 0 {
		if reset, err := a.Repo.UserSetLockoutState(ctx, user.ID, 0, nil, true); err != nil {
			xlog.Warn("failed to reset failed login attempt counter after mfa disable success", "user_id", user.ID, "err", err)
		} else {
			user = reset
		}
	}

	empty := ""
	user.MfaSecret = &empty
	if _, err := a.Repo.UserUpdate(ctx, user); err != nil {
		xlog.Error("failed to clear mfa secret", "user_id", user.ID, "err", err)
		return err
	}
	user.MfaEnabled = false
	if _, err := a.Repo.UserSetMFAEnabled(ctx, user.ID, false); err != nil {
		xlog.Error("failed to disable mfa", "user_id", user.ID, "err", err)
		return err
	}

	// Scoped to recovery/pre-auth tokens specifically -- disabling MFA
	// shouldn't collaterally revoke the user's sessions, API keys, or
	// trusted devices.
	if err := a.Repo.TokenRevokeAllByUserIDAndType(ctx, user.ID, models.TokenTypeMFARecovery); err != nil {
		xlog.Warn("failed to revoke recovery tokens after mfa disable", "user_id", user.ID, "err", err)
	}
	if err := a.Repo.TokenRevokeAllByUserIDAndType(ctx, user.ID, models.TokenTypeMFAPreAuth); err != nil {
		xlog.Warn("failed to revoke preauth tokens after mfa disable", "user_id", user.ID, "err", err)
	}

	xlog.Info("mfa disabled", "user_id", user.ID)
	return nil
}

// MFALoginVerify completes a step-up login: it validates the pre-auth token issued
// by CompleteBasicLogin and a TOTP or recovery code, then mints real session tokens.
// When rememberDevice is true, it also issues a trusted-device token (see
// TrustDevice) so future logins from the same device can skip this step-up for
// Cfg.TrustedDevice.TTL; deviceToken is empty when rememberDevice is false.
//
// When Cfg.AccountLockout.Enabled, an invalid code counts against the same
// failed-attempt counter and lockout as a wrong password (recordFailedLogin/
// checkAccountActive), so repeated guessing against a still-valid pre-auth
// token locks the account instead of being limited only by the (optional,
// IP-keyed) global rate limiter.
func (a *Auth) MFALoginVerify(ctx context.Context, mfaToken, code string, rememberDevice bool) (user *models.User, tokens *TokenResponse, deviceToken string, err error) {
	token, err := a.Repo.TokenGetByToken(ctx, util.HashToken(mfaToken))
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

	if a.Cfg.AccountLockout.Enabled {
		if user, err = a.checkAccountActive(ctx, user); err != nil {
			xlog.Debug("mfa login verify failed: account locked", "user_id", user.ID, "err", err)
			return nil, nil, "", err
		}
	}

	if !a.mfaValidateAnyCode(ctx, user, code) {
		xlog.Debug("mfa login verify failed: invalid code", "user_id", user.ID)
		if a.Cfg.AccountLockout.Enabled {
			a.recordFailedLogin(ctx, user)
		}
		return nil, nil, "", ErrInvalidMFACode
	}

	if user.FailedLoginAttempts > 0 {
		if reset, err := a.Repo.UserSetLockoutState(ctx, user.ID, 0, nil, true); err != nil {
			xlog.Warn("failed to reset failed login attempt counter after mfa success", "user_id", user.ID, "err", err)
		} else {
			user = reset
		}
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
//
// A recovery code is single-use by construction (mfaConsumeRecoveryCode
// deletes its token on success), but a bare totp.Validate call has no such
// protection: a valid code stays usable for the rest of its ~30s window
// (plus the ±1 step skew) and can be replayed into a second,
// attacker-controlled session if captured (phishing, shoulder-surfing).
// totpValidateWithReplayProtection closes that window per RFC 6238 §5.2 by
// requiring each accepted code to use a strictly later timestep than the
// last one that succeeded.
func (a *Auth) mfaValidateAnyCode(ctx context.Context, user *models.User, code string) bool {
	if user.MfaSecret != nil && *user.MfaSecret != "" {
		if ok, counter := totpValidateWithReplayProtection(code, *user.MfaSecret, user.MFALastTOTPCounter, time.Now()); ok {
			user.MFALastTOTPCounter = &counter
			if _, err := a.Repo.UserUpdate(ctx, user); err != nil {
				// Best-effort: the current login/step-up still succeeds, but
				// without this the same code could be replayed once more --
				// logged so it's visible, not silently swallowed.
				xlog.Warn("failed to persist mfa last-accepted totp counter", "user_id", user.ID, "err", err)
			}
			return true
		}
	}
	return a.mfaConsumeRecoveryCode(ctx, user, code)
}

// totpValidateWithReplayProtection re-implements totp.Validate's matching
// logic (30s period, ±1 step skew, compatible with Google Authenticator and
// most clients) instead of calling it directly, because totp.Validate only
// returns a bool -- it doesn't say which timestep matched, and that's
// exactly what's needed to reject a timestep that already succeeded once.
// lastCounter is the previously accepted counter (nil if none yet); on a
// match it returns the counter that matched, which the caller must persist
// as the new lastCounter.
func totpValidateWithReplayProtection(code, secret string, lastCounter *int64, now time.Time) (bool, int64) {
	current := int64(math.Floor(float64(now.Unix()) / 30))
	for _, counter := range []int64{current, current + 1, current - 1} {
		if counter < 0 || (lastCounter != nil && counter <= *lastCounter) {
			continue
		}
		ok, err := hotp.ValidateCustom(code, uint64(counter), secret, hotp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err == nil && ok {
			return true, counter
		}
	}
	return false, 0
}

func mfaHashRecoveryCode(userID, code string) string {
	sum := sha256.Sum256([]byte(userID + ":" + code))
	return hex.EncodeToString(sum[:])
}

func (a *Auth) mfaGenerateRecoveryCodes(ctx context.Context, user *models.User) ([]string, error) {
	// Any previously issued, still-unused recovery codes are invalidated by
	// re-enrollment so old codes can't be replayed against a new secret --
	// scoped to recovery codes specifically, so this doesn't collaterally
	// revoke the user's sessions/API keys/trusted devices.
	if err := a.Repo.TokenRevokeAllByUserIDAndType(ctx, user.ID, models.TokenTypeMFARecovery); err != nil {
		xlog.Warn("failed to revoke old mfa recovery codes before issuing new ones", "user_id", user.ID, "err", err)
	}

	codes := make([]string, 0, mfaRecoveryCodeCount)
	tokens := make([]*models.Token, 0, mfaRecoveryCodeCount)
	for i := 0; i < mfaRecoveryCodeCount; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)

		tokens = append(tokens, &models.Token{
			UserID:    user.ID,
			Token:     mfaHashRecoveryCode(user.ID, code),
			TokenType: models.TokenTypeMFARecovery,
			ExpiresAt: time.Now().AddDate(10, 0, 0),
			CreatedAt: time.Now(),
			Metadata:  models.JSONMap{},
		})
	}
	if err := a.Repo.TokenBatchInsert(ctx, tokens); err != nil {
		return nil, err
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

// recoveryCodeBytes is 16 random bytes (128 bits) per code. MFA recovery
// codes bypass MFA entirely on a successful match, so they need entropy in
// the same range as the other high-entropy tokens in this codebase
// (util.HashToken's doc comment), not the ~40 bits a shorter code would
// give a DB-leak attacker -- at 5 bytes, each code was recoverable from its
// stored hash in minutes on a GPU.
const recoveryCodeBytes = 16

func generateRecoveryCode() (string, error) {
	b := make([]byte, recoveryCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s-%s-%s", hex.EncodeToString(b[:4]), hex.EncodeToString(b[4:8]), hex.EncodeToString(b[8:12]), hex.EncodeToString(b[12:])), nil
}
