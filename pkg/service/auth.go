package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/josuebrunel/gopkg/xlog"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

// RequestBasicAuth defines the parameters for basic authentication (email/password).
type RequestBasicAuth struct {
	Email     string         `json:"email"`
	Username  string         `json:"username"`
	Password  string         `json:"password"`
	FirstName string         `json:"first_name"`
	LastName  string         `json:"last_name"`
	Locale    string         `json:"locale"`
	Timezone  string         `json:"timezone"`
	Phone     string         `json:"phone"`
	AvatarURL string         `json:"avatar_url"`
	Nickname  string         `json:"nickname"`
	Data      map[string]any `json:"data"`
}

// RequestPasswordReset defines the parameters for requesting a password reset.
type RequestPasswordReset struct {
	Email string `json:"email"`
}

// RequestPasswordResetConfirm defines the parameters for confirming a password reset.
type RequestPasswordResetConfirm struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,30}$`)

func normalizeUserInput(req *RequestBasicAuth) error {
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Username = strings.TrimSpace(req.Username)
	req.FirstName = strings.TrimSpace(req.FirstName)
	req.LastName = strings.TrimSpace(req.LastName)
	req.Nickname = strings.TrimSpace(req.Nickname)
	req.Phone = strings.TrimSpace(req.Phone)

	if err := validateEmail(req.Email); err != nil {
		return err
	}

	if req.Username != "" && !usernameRegex.MatchString(req.Username) {
		return errors.New("username must be 3-30 characters: letters, numbers, underscores, hyphens")
	}
	return nil
}

// validateEmail rejects anything that isn't a single well-formed address.
// This is the only gate before an email is persisted and later used
// verbatim as an SMTP recipient/header value, so it must reject embedded
// CR/LF and "Name <addr>" style values, not just malformed addresses.
func validateEmail(email string) error {
	if strings.ContainsAny(email, "\r\n") {
		return errors.New("invalid email address")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return errors.New("invalid email address")
	}
	return nil
}

// UserCreate creates a new user with email and password.
func (a *Auth) UserCreate(ctx context.Context, req *RequestBasicAuth) (*models.User, error) {
	xlog.Debug("creating user", "email", req.Email)
	if err := normalizeUserInput(req); err != nil {
		return nil, err
	}
	if err := a.validatePassword(req.Password); err != nil {
		xlog.Debug("password validation failed", "email", req.Email, "err", err)
		return nil, err
	}
	hash, err := a.UserHashPassword(req.Password)
	if err != nil {
		xlog.Error("failed to hash password", "email", req.Email, "err", err)
		return nil, err
	}
	user := &models.User{
		Email:        req.Email,
		Username:     req.Username,
		PasswordHash: hash,
		UserMetadata: req.Data,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Locale:       req.Locale,
		Timezone:     req.Timezone,
		Phone:        req.Phone,
		AvatarURL:    req.AvatarURL,
		Nickname:     req.Nickname,
		Provider:     "local",
	}
	u, err := a.Repo.UserCreate(ctx, user)
	if err != nil {
		// user.ID is already populated here even on failure: the
		// repository layer assigns it client-side before attempting the
		// insert, and user is the same struct pointer passed through.
		xlog.Error("failed to create user", "user_id", user.ID, "err", err)
		return nil, err
	}
	xlog.Info("user created", "id", u.ID, "email", u.Email)
	return u, nil
}

// UserHashPassword generates a password hash using the configured algorithm.
func (a *Auth) UserHashPassword(password string) (string, error) {
	switch a.Cfg.Hashing.Algorithm {
	case "argon2id":
		return argon2idHash(password, a.Cfg.Hashing)
	default:
		cost := a.Cfg.Hashing.BcryptCost
		if cost == 0 {
			cost = 14 // preserves prior behavior for configs built without LoadConfig (e.g. tests)
		}
		bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
		return string(bytes), err
	}
}

// verifyPassword verifies a password against its hash, auto-detecting the algorithm.
func verifyPassword(password, encodedHash string) bool {
	switch {
	case strings.HasPrefix(encodedHash, "$2a$") || strings.HasPrefix(encodedHash, "$2b$"):
		return bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password)) == nil
	case strings.HasPrefix(encodedHash, "$argon2id$"):
		return verifyArgon2idHash(password, encodedHash)
	default:
		return false
	}
}

func argon2idHash(password string, cfg config.Hashing) (string, error) {
	// argon2.IDKey panics on out-of-range parameters (e.g. time=0), and a zero-value
	// config here means LoadConfig never populated these fields, so validate up front.
	if cfg.Argon2Iterations < 1 {
		return "", fmt.Errorf("argon2: iterations must be at least 1, got %d", cfg.Argon2Iterations)
	}
	if cfg.Argon2Memory < 8*cfg.Argon2Parallelism {
		return "", fmt.Errorf("argon2: memory must be at least 8*parallelism (%d), got %d", 8*cfg.Argon2Parallelism, cfg.Argon2Memory)
	}
	if cfg.Argon2Parallelism < 1 {
		return "", fmt.Errorf("argon2: parallelism must be at least 1, got %d", cfg.Argon2Parallelism)
	}
	if cfg.Argon2SaltLength < 1 {
		return "", fmt.Errorf("argon2: salt length must be at least 1, got %d", cfg.Argon2SaltLength)
	}
	if cfg.Argon2KeyLength < 1 {
		return "", fmt.Errorf("argon2: key length must be at least 1, got %d", cfg.Argon2KeyLength)
	}

	salt := make([]byte, cfg.Argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, uint32(cfg.Argon2Iterations), uint32(cfg.Argon2Memory), uint8(cfg.Argon2Parallelism), uint32(cfg.Argon2KeyLength))
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", cfg.Argon2Memory, cfg.Argon2Iterations, cfg.Argon2Parallelism, b64Salt, b64Hash), nil
}

func verifyArgon2idHash(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}
	var version int
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != 19 {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	computed := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(computed, expectedHash) == 1
}

func (a *Auth) validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	if len(password) > 128 {
		return errors.New("password must be at most 128 characters long")
	}
	return nil
}

// ErrAccountLocked is returned when an account is temporarily locked after too
// many consecutive failed login attempts.
var ErrAccountLocked = errors.New("account is temporarily locked due to too many failed login attempts")

// ErrAccountDisabled is returned when an account's IsActive gate is off for a
// reason other than brute-force lockout (e.g. an administrative suspension),
// so it has no LockedUntil expiry and won't auto-recover.
var ErrAccountDisabled = errors.New("account is disabled")

// autoUnlockIfExpired clears a user's brute-force lockout bookkeeping once
// LockedUntil has passed, matching UserAuthenticate's auto-unlock-on-next-
// attempt behavior. Shared with the MFA/SMS OTP step-up flows below, which
// enforce the same account-level lockout against repeated code guesses.
// Returns user unchanged if it isn't locked, the lock hasn't expired yet, or
// the update fails (logged, not returned, so callers keep failing closed on
// the pre-update state).
//
// FailedLoginAttempts is deliberately preserved across this unlock (not
// reset to 0) so recordFailedLogin's exponential backoff keeps escalating
// across repeated lockout cycles instead of restarting fresh every time a
// lockout expires -- only an actual successful login resets it.
func (a *Auth) autoUnlockIfExpired(ctx context.Context, user *models.User) *models.User {
	if user.IsActive || user.LockedUntil == nil || !time.Now().After(*user.LockedUntil) {
		return user
	}
	unlocked, err := a.Repo.UserSetLockoutState(ctx, user.ID, user.FailedLoginAttempts, nil, true)
	if err != nil {
		xlog.Error("failed to auto-unlock account", "user_id", user.ID, "err", err)
		return user
	}
	return unlocked
}

// checkAccountActive auto-unlocks user if its lockout window has passed,
// then returns ErrAccountLocked/ErrAccountDisabled if it's still inactive.
// Used by the MFA and SMS OTP verification flows so a brute-force lockout
// triggered by repeated invalid codes (recorded via recordFailedLogin, same
// counter as password brute force) actually blocks further attempts,
// instead of only affecting a future password login.
func (a *Auth) checkAccountActive(ctx context.Context, user *models.User) (*models.User, error) {
	user = a.autoUnlockIfExpired(ctx, user)
	if !user.IsActive {
		if user.LockedUntil != nil {
			return user, ErrAccountLocked
		}
		return user, ErrAccountDisabled
	}
	return user, nil
}

// UserAuthenticate authenticates a user with email and password. It enforces
// the IsActive gate and brute-force lockout: after Cfg.AccountLockout.MaxAttempts
// consecutive failed attempts, the account is locked (IsActive cleared) for
// Cfg.AccountLockout.LockoutDuration, then auto-unlocked on the next attempt
// after that window passes.
func (a *Auth) UserAuthenticate(ctx context.Context, req RequestBasicAuth) (*models.User, error) {
	xlog.Debug("authenticating user", "email", req.Email)
	user, err := a.Repo.UserGetByEmail(ctx, req.Email)
	if err != nil {
		xlog.Debug("authentication failed: user not found", "email", req.Email, "err", err)
		verifyPassword(req.Password, a.getDummyPasswordHash())
		return nil, errors.New("invalid credentials")
	}

	user = a.autoUnlockIfExpired(ctx, user)

	// Always run the password comparison, even on an inactive account, so a
	// locked/disabled account's response takes the same time as a wrong-password
	// response and doesn't leak account state via timing.
	passwordOK := verifyPassword(req.Password, user.PasswordHash)

	if !user.IsActive {
		xlog.Debug("authentication failed: account not active", "user_id", user.ID)
		if user.LockedUntil != nil {
			return nil, ErrAccountLocked
		}
		return nil, ErrAccountDisabled
	}

	if !passwordOK {
		xlog.Debug("authentication failed: invalid credentials", "email", req.Email)
		if err := a.Hook.AfterLoginFailed(ctx, user, "invalid_password"); err != nil {
			xlog.Error("hook AfterLoginFailed failed", "user_id", user.ID, "err", err)
		}
		if a.Cfg.AccountLockout.Enabled {
			a.recordFailedLogin(ctx, user)
		}
		return nil, errors.New("invalid credentials")
	}

	if user.FailedLoginAttempts > 0 {
		if reset, err := a.Repo.UserSetLockoutState(ctx, user.ID, 0, nil, true); err != nil {
			xlog.Warn("failed to reset failed login attempt counter", "user_id", user.ID, "err", err)
		} else {
			user = reset
		}
	}

	xlog.Info("user authenticated", "id", user.ID, "email", user.Email)
	return user, nil
}

// maxLockoutDuration caps recordFailedLogin's exponential backoff, so a
// sustained flood of failed attempts can't extend a lockout indefinitely.
const maxLockoutDuration = 24 * time.Hour

// recordFailedLogin increments a user's failed-login counter and, once it
// reaches Cfg.AccountLockout.MaxAttempts, locks the account. The counter is
// incremented atomically at the DB layer (UserIncrementFailedLoginAttempts)
// rather than computed here from the already-fetched user and written back,
// so concurrent failed logins against the same account can't race on a
// stale read and undercount attempts.
//
// The lockout duration doubles each additional MaxAttempts-sized batch of
// failures (capped at maxLockoutDuration): a fixed-duration lockout keyed
// purely on the account is a repeatable, indefinite DoS otherwise -- an
// attacker who only wants to deny a victim access, not actually guess the
// password, can keep the account locked forever by sending MaxAttempts
// wrong guesses every LockoutDuration once it auto-expires. autoUnlockIfExpired
// preserves FailedLoginAttempts across that auto-expiry (rather than
// resetting it to 0) specifically so this backoff keeps escalating across
// cycles; only an actual successful login resets it back to 0.
func (a *Auth) recordFailedLogin(ctx context.Context, user *models.User) {
	updated, err := a.Repo.UserIncrementFailedLoginAttempts(ctx, user.ID)
	if err != nil {
		xlog.Error("failed to record failed login attempt", "user_id", user.ID, "err", err)
		return
	}

	if updated.FailedLoginAttempts < a.Cfg.AccountLockout.MaxAttempts {
		return
	}

	multiplier := updated.FailedLoginAttempts / a.Cfg.AccountLockout.MaxAttempts
	duration := a.Cfg.AccountLockout.LockoutDuration * time.Duration(1<<min(multiplier-1, 10))
	if duration <= 0 || duration > maxLockoutDuration {
		duration = maxLockoutDuration
	}
	until := time.Now().Add(duration)

	xlog.Warn("account locked after too many failed login attempts", "user_id", user.ID, "attempts", updated.FailedLoginAttempts, "lockout_duration", duration)
	if _, err := a.Repo.UserSetLockoutState(ctx, user.ID, updated.FailedLoginAttempts, &until, false); err != nil {
		xlog.Error("failed to lock account", "user_id", user.ID, "err", err)
		return
	}
	if err := a.Hook.AfterAccountLocked(ctx, user); err != nil {
		xlog.Error("hook AfterAccountLocked failed", "user_id", user.ID, "err", err)
	}
}

// dummyPassword is hashed once, lazily, by getDummyPasswordHash -- see the
// Auth.dummyPasswordHash* field docs for why it can't be a hardcoded literal.
const dummyPassword = "correct-horse-battery-staple-never-checked-against-anything-real"

// getDummyPasswordHash returns a password hash produced with the currently
// configured algorithm/cost/params, computing it on first call and caching
// it for the lifetime of a. If hashing itself fails (e.g. an invalid Argon2
// config), it logs the failure and returns "" -- verifyPassword treats an
// unrecognized hash format as a fast, safe non-match; the same broken
// config would also fail every real UserHashPassword call, so this doesn't
// introduce a new failure mode, only degrades the timing-equalization
// protection under an already-broken configuration.
func (a *Auth) getDummyPasswordHash() string {
	a.dummyPasswordHashOnce.Do(func() {
		hash, err := a.UserHashPassword(dummyPassword)
		if err != nil {
			xlog.Error("failed to precompute dummy password hash; account-enumeration timing protection is degraded", "err", err)
			return
		}
		a.dummyPasswordHash = hash
	})
	return a.dummyPasswordHash
}

// otpResendCooldown is the minimum time between two live codes/links of the
// same type for the same user -- see checkResendCooldown. A var (not a
// const) purely so tests can shrink it instead of waiting out a real minute.
var otpResendCooldown = 60 * time.Second

// ErrResendTooSoon is returned by PasswordlessRequest/SMSOTPRequest when a
// still-live code/link of the same type was already issued for the same
// address/phone within otpResendCooldown.
var ErrResendTooSoon = errors.New("please wait before requesting another code")

// checkResendCooldown returns ErrResendTooSoon if a still-unexpired token of
// tokenType already exists for userID, created less than otpResendCooldown
// ago. This is a per-address/per-phone throttle independent of the
// general-purpose IP rate limiter: PasswordlessRequest/SMSOTPRequest create
// a user (if one doesn't already exist) and send a real email or a billable
// SMS on every call with no authentication required, so a caller spreading
// requests across many source IPs could otherwise spam or SMS-bomb a single
// target regardless of any per-IP limit.
func (a *Auth) checkResendCooldown(ctx context.Context, userID, tokenType string) error {
	existing, err := a.Repo.TokenListByUserIDAndType(ctx, userID, tokenType)
	if err != nil {
		return err
	}
	for _, tok := range existing {
		if time.Now().After(tok.ExpiresAt) {
			continue
		}
		// elapsed is clamped to 0 rather than compared directly: MySQL's
		// DATETIME columns (no fractional-seconds precision) round
		// CreatedAt to the nearest second on write, which can make it read
		// back as slightly in the future and produce a negative duration
		// here. Without the clamp, that negative value satisfies "< cooldown"
		// even once the real cooldown has fully elapsed.
		elapsed := time.Since(tok.CreatedAt)
		if elapsed < 0 {
			elapsed = 0
		}
		if elapsed < otpResendCooldown {
			return ErrResendTooSoon
		}
	}
	return nil
}

// UserUpdatePassword updates the password for a user.
func (a *Auth) UserUpdatePassword(ctx context.Context, user *models.User, password string) (*models.User, error) {
	if err := a.validatePassword(password); err != nil {
		return nil, err
	}
	hash, err := a.UserHashPassword(password)
	if err != nil {
		return nil, err
	}
	user.PasswordHash = hash
	return a.Repo.UserUpdate(ctx, user)
}

// UserUpdate updates the user information.
func (a *Auth) UserUpdate(ctx context.Context, user *models.User) (*models.User, error) {
	return a.Repo.UserUpdate(ctx, user)
}

// UserDelete deletes a user by ID.
func (a *Auth) UserDelete(ctx context.Context, id string) error {
	return a.Repo.UserDelete(ctx, id)
}

// PasswordResetRequest initiates the password reset flow.
func (a *Auth) PasswordResetRequest(ctx context.Context, req RequestPasswordReset) error {
	user, err := a.Repo.UserGetByEmail(ctx, req.Email)
	if err != nil {
		// Equalize timing with the known-email path below (token generation,
		// a DB write, and an SMTP send) so an anonymous caller can't infer
		// account existence from response latency alone. Burns comparable
		// CPU/DB cost -- generating a token and a harmless DB read -- without
		// emailing anyone or writing a token row nothing will ever consume.
		_, _ = a.generateRefreshToken()
		_, _ = a.Repo.UserGetByID(ctx, util.NewID())
		return nil
	}

	tokenValue, err := a.generateRefreshToken()
	if err != nil {
		return err
	}

	token := &models.Token{
		UserID:    user.ID,
		Token:     util.HashToken(tokenValue),
		TokenType: models.TokenTypePasswordReset,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
		Revoked:   false,
		Metadata:  models.JSONMap{},
	}

	if _, err := a.Repo.TokenCreate(ctx, token); err != nil {
		return err
	}

	prefix := a.PathPrefix
	if prefix != "" {
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		prefix = strings.TrimSuffix(prefix, "/")
	}

	link := fmt.Sprintf("%s%s/password-reset/confirm?token=%s", a.Cfg.BaseURL, prefix, tokenValue)

	data := EmailTemplateData{
		Link:  link,
		Token: tokenValue,
		Email: user.Email,
	}
	subject := RenderTemplate(a.Cfg.EmailTemplates.PasswordResetSubject, data)
	body := RenderTemplate(a.Cfg.EmailTemplates.PasswordResetBody, data)

	return a.Mailer.Send(user.Email, subject, body)
}

// PasswordResetConfirm completes the password reset flow.
func (a *Auth) PasswordResetConfirm(ctx context.Context, req RequestPasswordResetConfirm) error {
	token, err := a.Repo.TokenGetByToken(ctx, util.HashToken(req.Token))
	if err != nil {
		return errors.New("invalid or expired token")
	}

	if token.TokenType != models.TokenTypePasswordReset {
		return errors.New("invalid token type")
	}

	if token.Revoked {
		return errors.New("token already used")
	}

	if time.Now().After(token.ExpiresAt) {
		return errors.New("token expired")
	}

	user, err := a.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		return err
	}

	if _, err := a.UserUpdatePassword(ctx, user, req.Password); err != nil {
		return err
	}

	if err := a.Repo.TokenRevokeAllByUserID(ctx, user.ID); err != nil {
		xlog.Error("failed to revoke all tokens after password reset", "user_id", user.ID, "err", err)
		return err
	}

	return a.Repo.TokenRevoke(ctx, token.ID)
}

// RequestPasswordless defines the parameters for requesting a magic link.
type RequestPasswordless struct {
	Email string `json:"email"`
}

// PasswordlessRequest initiates the passwordless (magic link) login flow.
func (a *Auth) PasswordlessRequest(ctx context.Context, req RequestPasswordless) error {
	xlog.Debug("passwordless login requested", "email", req.Email)

	user, err := a.Repo.UserGetByEmail(ctx, req.Email)
	if err != nil {

		xlog.Debug("creating temporary user for passwordless login", "email", req.Email)
		user = &models.User{
			Email:         req.Email,
			Provider:      "local",
			EmailVerified: false,
		}
		user, err = a.Repo.UserCreate(ctx, user)
		if err != nil {
			xlog.Error("failed to create temporary user", "email", req.Email, "err", err)
			return err
		}
	}

	if err := a.checkResendCooldown(ctx, user.ID, models.TokenTypePasswordless); err != nil {
		return err
	}

	tokenValue, err := a.generateRefreshToken()
	if err != nil {
		xlog.Error("failed to generate token", "err", err)
		return err
	}

	token := &models.Token{
		UserID:    user.ID,
		Token:     util.HashToken(tokenValue),
		TokenType: models.TokenTypePasswordless,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		CreatedAt: time.Now(),
	}

	if _, err := a.Repo.TokenCreate(ctx, token); err != nil {
		xlog.Error("failed to save passwordless token", "user_id", user.ID, "err", err)
		return err
	}

	prefix := a.PathPrefix
	if prefix != "" {
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		prefix = strings.TrimSuffix(prefix, "/")
	}

	link := fmt.Sprintf("%s%s/passwordless/login?token=%s", a.Cfg.BaseURL, prefix, tokenValue)

	data := EmailTemplateData{
		Link:  link,
		Token: tokenValue,
		Email: user.Email,
	}
	subject := RenderTemplate(a.Cfg.EmailTemplates.PasswordlessSubject, data)
	body := RenderTemplate(a.Cfg.EmailTemplates.PasswordlessBody, data)

	// user.Email (normalized/lowercased), not req.Email (whatever casing the
	// caller typed) -- matches PasswordResetRequest's already-correct
	// pattern, so the sent-to address and template data always reflect the
	// canonical stored address regardless of input casing.
	if err := a.Mailer.Send(user.Email, subject, body); err != nil {
		xlog.Error("failed to send passwordless email", "email", user.Email, "err", err)
		return err
	}
	xlog.Info("passwordless login email sent", "email", user.Email)
	return nil
}

// PasswordlessLogin completes the passwordless login flow.
func (a *Auth) PasswordlessLogin(ctx context.Context, tokenValue string) (*TokenResponse, error) {
	xlog.Debug("processing passwordless login")
	token, err := a.Repo.TokenGetByToken(ctx, util.HashToken(tokenValue))
	if err != nil {
		xlog.Debug("passwordless token not found", "err", err)
		return nil, errors.New("invalid or expired magic link")
	}

	if token.TokenType != models.TokenTypePasswordless {
		xlog.Warn("invalid token type for passwordless login", "type", token.TokenType)
		return nil, errors.New("invalid token type")
	}

	if time.Now().After(token.ExpiresAt) || token.Revoked {
		if err := a.Repo.TokenRevoke(ctx, token.ID); err != nil {
			xlog.Error("failed to revoke expired/already-revoked passwordless token", "token_id", token.ID, "err", err)
		}
		xlog.Debug("passwordless token expired or revoked", "token_id", token.ID)
		return nil, errors.New("magic link expired")
	}

	user, err := a.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		xlog.Error("failed to get user for passwordless login", "user_id", token.UserID, "err", err)
		return nil, err
	}

	if !user.EmailVerified {
		if _, err := a.Repo.UserSetEmailVerified(ctx, user.ID, true); err != nil {
			xlog.Error("failed to update user email verification", "user_id", user.ID, "err", err)
			return nil, err
		}
	}

	if err := a.Repo.TokenRevoke(ctx, token.ID); err != nil {
		xlog.Error("failed to revoke passwordless token", "token_id", token.ID, "err", err)
		return nil, err
	}

	resp, err := a.TokenCreate(ctx, user)
	if err != nil {
		return nil, err
	}
	xlog.Info("passwordless login successful", "user_id", user.ID)
	return resp, nil
}

// OAuth2UserInfo represents the user information retrieved from an OAuth2 provider.
type OAuth2UserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// OAuth2Provider represents a custom OAuth2/OIDC provider registration.
type OAuth2Provider struct {
	Config     oauth2.Config
	UserInfoFn func(ctx context.Context, token *oauth2.Token) (*OAuth2UserInfo, error)
}

// RegisterOAuth2Provider registers a custom OAuth2/OIDC provider.
func (a *Auth) RegisterOAuth2Provider(name string, p OAuth2Provider) {
	a.customProvidersMu.Lock()
	defer a.customProvidersMu.Unlock()
	a.customProviders[name] = p
}

// OAuth2GetConfig returns the OAuth2 configuration for the given provider.
func (a *Auth) OAuth2GetConfig(provider string) (*oauth2.Config, error) {
	a.customProvidersMu.RLock()
	p, ok := a.customProviders[provider]
	a.customProvidersMu.RUnlock()
	if ok {
		cfgCopy := p.Config
		return &cfgCopy, nil
	}
	return nil, fmt.Errorf("unsupported provider: %s", provider)
}

// OAuth2GetUserInfo retrieves user information from the OAuth2 provider using the given token.
func (a *Auth) OAuth2GetUserInfo(ctx context.Context, provider string, token *oauth2.Token) (*OAuth2UserInfo, error) {
	a.customProvidersMu.RLock()
	p, ok := a.customProviders[provider]
	a.customProvidersMu.RUnlock()
	if ok {
		if p.UserInfoFn == nil {
			return nil, fmt.Errorf("provider %s does not have UserInfoFn configured", provider)
		}
		return p.UserInfoFn(ctx, token)
	}
	return nil, fmt.Errorf("unsupported provider: %s", provider)
}

// OAuth2Authenticate authenticates a user using OAuth2 information.
// It links the OAuth2 account to an existing user or creates a new one.
func (a *Auth) OAuth2Authenticate(ctx context.Context, provider string, userInfo *OAuth2UserInfo) (*models.User, error) {
	xlog.Debug("authenticating via oauth2", "provider", provider, "email", userInfo.Email, "provider_id", userInfo.ID)
	userInfo.Email = strings.ToLower(strings.TrimSpace(userInfo.Email))

	user, err := a.Repo.UserGetByProvider(ctx, provider, userInfo.ID)
	if err == nil && user != nil {

		if userInfo.Email != "" && user.Email != userInfo.Email {
			user.Email = userInfo.Email
			u, err := a.Repo.UserUpdate(ctx, user)
			if err != nil {
				xlog.Error("failed to update user email from provider", "user_id", user.ID, "err", err)
				return nil, err
			}
			xlog.Info("user authenticated via oauth2", "user_id", user.ID, "provider", provider)
			return u, nil
		}
		xlog.Info("user authenticated via oauth2", "user_id", user.ID, "provider", provider)
		return user, nil
	}

	if userInfo.Email != "" && userInfo.EmailVerified {
		user, err = a.Repo.UserGetByEmail(ctx, userInfo.Email)
		if err == nil && user != nil {

			user.Provider = provider
			user.ProviderID = &userInfo.ID
			u, err := a.Repo.UserUpdate(ctx, user)
			if err != nil {
				xlog.Error("failed to link provider to existing user", "user_id", user.ID, "provider", provider, "err", err)
				return nil, err
			}
			xlog.Info("linked provider to existing user", "user_id", user.ID, "provider", provider)
			return u, nil
		}
	}

	user = &models.User{
		Email:         userInfo.Email,
		Provider:      provider,
		ProviderID:    &userInfo.ID,
		EmailVerified: true,
	}

	u, err := a.Repo.UserCreate(ctx, user)
	if err != nil {
		xlog.Error("failed to create user from oauth2", "provider", provider, "err", err)
		return nil, err
	}
	xlog.Info("created new user via oauth2", "user_id", u.ID, "provider", provider)
	return u, nil
}

// TokenResponse defines the structure of the token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// impersonationRefreshTokenTTL is the refresh-token lifetime for an
// impersonation session -- see tokenCreateForActor's doc comment for why
// it's much shorter than a normal session's.
const impersonationRefreshTokenTTL = 1 * time.Hour

// TokenCreate creates a new pair of access and refresh tokens for the given user.
func (a *Auth) TokenCreate(ctx context.Context, user *models.User) (*TokenResponse, error) {
	return a.tokenCreateForActor(ctx, user, "", "")
}

// tokenCreateForActor creates a new pair of access and refresh tokens for the given user.
// When actorID is non-empty, the access token carries an "act" claim identifying the
// acting user (e.g. an admin impersonating user), and the persisted refresh token is
// tagged in Metadata so it can be recognized and revoked as an impersonation token.
//
// familyID identifies the refresh-token's rotation lineage: pass "" to start a new
// family (fresh login/impersonation), or an existing token's family id to carry it
// forward across a rotation (see TokenRefresh). It's persisted in Metadata so a replay
// of an already-rotated-out token can be traced back to, and used to revoke, the rest
// of its family.
//
// This is the single choke point every session-minting flow funnels through
// (TokenCreate -- and so PasswordlessLogin, OAuth2Authenticate,
// WebauthnLoginFinish, MFA/SMS-OTP verification -- plus TokenRefresh and
// Impersonate directly), so checkAccountActive is enforced here
// unconditionally rather than at each entry point individually: before this,
// IsActive was only checked by the password-login path, and every other way
// to obtain a session (a pre-suspension refresh token, a fresh magic link,
// OAuth2, a passkey) kept working against a suspended/disabled account.
func (a *Auth) tokenCreateForActor(ctx context.Context, user *models.User, actorID, familyID string) (*TokenResponse, error) {
	user, err := a.checkAccountActive(ctx, user)
	if err != nil {
		xlog.Warn("token mint refused: account not active", "user_id", user.ID, "actor_id", actorID, "err", err)
		return nil, err
	}

	xlog.Debug("creating tokens", "user_id", user.ID, "actor_id", actorID)
	accessToken, exp, err := a.generateAccessToken(user, actorID)
	if err != nil {
		xlog.Error("failed to generate access token", "user_id", user.ID, "err", err)
		return nil, err
	}

	refreshToken, err := a.generateRefreshToken()
	if err != nil {
		xlog.Error("failed to generate refresh token", "user_id", user.ID, "err", err)
		return nil, err
	}

	if familyID == "" {
		familyID = util.NewIDStripped()
	}
	metadata := models.JSONMap{"family_id": familyID}

	// Impersonation sessions get a much shorter refresh-token lifetime than
	// a normal session's 30 days: nothing here re-validates the acting
	// admin's role on refresh (TokenRefresh only looks up the impersonated
	// target, never the actor), so a revoked admin's already-issued
	// impersonation token would otherwise keep working via refresh for the
	// full 30-day window. impersonationRefreshTokenTTL bounds that exposure
	// instead -- once it lapses, resuming impersonation requires a fresh
	// Impersonate call, which (via the HTTP route's admin-authz gate, or
	// whatever check the caller wraps around the library method) re-checks
	// the admin's *current* role.
	refreshTokenTTL := 30 * 24 * time.Hour
	if actorID != "" {
		metadata["impersonation"] = true
		metadata["actor_id"] = actorID
		refreshTokenTTL = impersonationRefreshTokenTTL
	}

	now := time.Now()
	token := &models.Token{
		UserID:    user.ID,
		Token:     util.HashToken(refreshToken),
		TokenType: models.TokenTypeRefresh,
		ExpiresAt: now.Add(refreshTokenTTL),
		CreatedAt: now,
		Revoked:   false,
		Metadata:  metadata,
	}

	if _, err := a.Repo.TokenCreate(ctx, token); err != nil {
		xlog.Error("failed to save refresh token", "user_id", user.ID, "err", err)
		return nil, err
	}

	nowActive := time.Now()
	user.LastActiveAt = &nowActive
	if _, err := a.Repo.UserUpdate(ctx, user); err != nil {
		xlog.Error("failed to update user last_active_at", "user_id", user.ID, "err", err)
	}

	xlog.Debug("tokens created", "user_id", user.ID)
	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(time.Until(exp).Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// Impersonate mints a new token pair for targetUserID, acting on behalf of adminUser.
// The resulting access token carries an "act" claim identifying adminUser, and the
// persisted refresh token is tagged as an impersonation token.
//
// ezauth performs no authorization check here: the caller is responsible for verifying
// that adminUser is allowed to impersonate (e.g. via adminUser.HasRole("admin")) before
// calling this method directly. Handler's built-in HTTP route (Impersonate) is
// different: it gates on Cfg.AdminRole by default (see handler.WithAdminAuthz).
func (a *Auth) Impersonate(ctx context.Context, adminUser *models.User, targetUserID string) (*TokenResponse, error) {
	if adminUser == nil {
		return nil, errors.New("acting admin user is required")
	}
	if targetUserID == "" {
		return nil, errors.New("target user id is required")
	}
	if targetUserID == adminUser.ID {
		return nil, errors.New("cannot impersonate yourself")
	}

	target, err := a.Repo.UserGetByID(ctx, targetUserID)
	if err != nil {
		xlog.Debug("impersonation failed: target user not found", "target_user_id", targetUserID)
		return nil, errors.New("target user not found")
	}

	xlog.Info("impersonation started", "admin_id", adminUser.ID, "target_user_id", target.ID)
	return a.tokenCreateForActor(ctx, target, adminUser.ID, "")
}

// StopImpersonating revokes an impersonation refresh token, ending that impersonation
// session server-side. callerID must match the token's actor_id (the admin who started
// the impersonation) -- without this check, any admin who obtained another admin's
// impersonation refresh token (logs, a shared terminal, ...) could end, or replay via
// TokenRefresh before this revokes it, a session they never started.
func (a *Auth) StopImpersonating(ctx context.Context, callerID, impersonationRefreshToken string) error {
	token, err := a.Repo.TokenGetByToken(ctx, util.HashToken(impersonationRefreshToken))
	if err != nil {
		xlog.Debug("stop impersonation failed: token not found", "err", err)
		return errors.New("invalid impersonation token")
	}
	if imp, _ := token.Metadata["impersonation"].(bool); !imp {
		return errors.New("not an impersonation token")
	}
	if actorID, _ := token.Metadata["actor_id"].(string); actorID != callerID {
		xlog.Warn("stop impersonation failed: caller is not the impersonation's actor", "token_id", token.ID, "caller_id", callerID)
		return errors.New("invalid impersonation token")
	}
	if err := a.Repo.TokenRevoke(ctx, token.ID); err != nil {
		xlog.Error("failed to revoke impersonation token", "token_id", token.ID, "err", err)
		return err
	}
	xlog.Info("impersonation ended", "token_id", token.ID, "user_id", token.UserID)
	return nil
}

// TokenRefresh refreshes the access and refresh tokens using a valid refresh token.
func (a *Auth) TokenRefresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	xlog.Debug("refreshing token")
	token, err := a.Repo.TokenGetByToken(ctx, util.HashToken(refreshToken))
	if err != nil {
		xlog.Debug("refresh token not found", "err", err)
		return nil, errors.New("invalid refresh token")
	}

	if token.Revoked {
		xlog.Warn("attempt to use revoked token", "token_id", token.ID, "user_id", token.UserID)
		if familyID, ok := token.Metadata["family_id"].(string); ok && familyID != "" {
			xlog.Error("refresh token reuse detected, revoking token family", "token_id", token.ID, "user_id", token.UserID, "family_id", familyID)
			a.revokeTokenFamily(ctx, token.UserID, familyID)
		}
		return nil, errors.New("token revoked")
	}

	if time.Now().After(token.ExpiresAt) {
		xlog.Debug("refresh token expired", "token_id", token.ID, "user_id", token.UserID)
		return nil, errors.New("token expired")
	}

	user, err := a.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		xlog.Error("failed to get user for refresh token", "user_id", token.UserID, "err", err)
		return nil, err
	}

	if err := a.Repo.TokenRevoke(ctx, token.ID); err != nil {
		xlog.Error("failed to revoke old refresh token", "token_id", token.ID, "err", err)
		return nil, err
	}

	actorID, _ := token.Metadata["actor_id"].(string)
	familyID, _ := token.Metadata["family_id"].(string)
	return a.tokenCreateForActor(ctx, user, actorID, familyID)
}

// revokeTokenFamily revokes every other active refresh token in the given rotation
// family, in response to a detected reuse (replay of an already-rotated-out token) —
// a strong signal the token was stolen. A single bulk UPDATE, not a list-then-loop.
func (a *Auth) revokeTokenFamily(ctx context.Context, userID, familyID string) {
	if err := a.Repo.TokenRevokeFamily(ctx, userID, familyID); err != nil {
		xlog.Error("failed to revoke token family", "user_id", userID, "family_id", familyID, "err", err)
	}
}

// TokenRevoke revokes the given refresh token, provided it belongs to
// userID. Returns ErrSessionNotFound if the token doesn't exist or belongs
// to a different user -- without this check, a caller who obtained (e.g.
// leaked/stolen) another user's refresh token value could revoke it, and
// authenticating as *some* user (which every caller of this method already
// is) was never sufficient proof that the token being revoked is theirs.
func (a *Auth) TokenRevoke(ctx context.Context, userID, refreshToken string) error {
	xlog.Info("revoking token")
	token, err := a.Repo.TokenGetByToken(ctx, util.HashToken(refreshToken))
	if err != nil || token.UserID != userID {
		xlog.Debug("token to revoke not found", "err", err)
		return ErrSessionNotFound
	}
	err = a.Repo.TokenRevoke(ctx, token.ID)
	if err != nil {
		xlog.Error("failed to revoke token", "token_id", token.ID, "err", err)
	} else {
		xlog.Info("token revoked", "token_id", token.ID)
	}
	return err
}

func (a *Auth) generateAccessToken(user *models.User, actorID string) (string, time.Time, error) {
	exp := time.Now().Add(1 * time.Hour)
	claims := jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"exp":   jwt.NewNumericDate(exp),
		"iat":   jwt.NewNumericDate(time.Now()),
	}
	if actorID != "" {
		claims["act"] = map[string]any{"sub": actorID}
	}
	token := jwt.NewWithClaims(a.jwtKeys.method, claims)
	if a.jwtKeys.keyID != "" {
		token.Header["kid"] = a.jwtKeys.keyID
	}
	t, err := token.SignedString(a.jwtKeys.signingKey)
	return t, exp, err
}

func (a *Auth) generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
