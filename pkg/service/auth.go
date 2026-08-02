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
		xlog.Error("failed to create user", "email", req.Email, "err", err)
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
		bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
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
	salt := make([]byte, cfg.Argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, cfg.Argon2Iterations, cfg.Argon2Memory, cfg.Argon2Parallelism, cfg.Argon2KeyLength)
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

// UserAuthenticate authenticates a user with email and password.
func (a *Auth) UserAuthenticate(ctx context.Context, req RequestBasicAuth) (*models.User, error) {
	xlog.Debug("authenticating user", "email", req.Email)
	user, err := a.Repo.UserGetByEmail(ctx, req.Email)
	if err != nil {
		xlog.Debug("authentication failed: user not found", "email", req.Email, "err", err)
		verifyPassword(req.Password, dummyHash(a.Cfg.Hashing.Algorithm))
		return nil, errors.New("invalid credentials")
	}

	if !verifyPassword(req.Password, user.PasswordHash) {
		xlog.Debug("authentication failed: invalid credentials", "email", req.Email)
		return nil, errors.New("invalid credentials")
	}
	xlog.Info("user authenticated", "id", user.ID, "email", user.Email)
	return user, nil
}

var dummyBcryptHash = "$2a$14$ggvoBThQ9l3LSe3o0Y5aKO5opqgoaDgMYONZvGwuN.7Duu/xUO36C"
var dummyArgon2Hash = "$argon2id$v=19$m=65536,t=3,p=4$rShbPuU7iV9LeKMS/It7kw$6WhU5zYIEInUzD/VX77WT81MYJxvGXw227Hm9sxPCQ0"

func dummyHash(algorithm string) string {
	if algorithm == "argon2id" {
		return dummyArgon2Hash
	}
	return dummyBcryptHash
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

		return nil
	}

	tokenValue, err := a.generateRefreshToken()
	if err != nil {
		return err
	}

	token := &models.Token{
		UserID:    user.ID,
		Token:     tokenValue,
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
	token, err := a.Repo.TokenGetByToken(ctx, req.Token)
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

// RequestPasswordlessLogin defines the parameters for logging in with a magic link.
type RequestPasswordlessLogin struct {
	Token string `json:"token"`
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

	tokenValue, err := a.generateRefreshToken()
	if err != nil {
		xlog.Error("failed to generate token", "err", err)
		return err
	}

	token := &models.Token{
		UserID:    user.ID,
		Token:     tokenValue,
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
		Email: req.Email,
	}
	subject := RenderTemplate(a.Cfg.EmailTemplates.PasswordlessSubject, data)
	body := RenderTemplate(a.Cfg.EmailTemplates.PasswordlessBody, data)

	if err := a.Mailer.Send(req.Email, subject, body); err != nil {
		xlog.Error("failed to send passwordless email", "email", req.Email, "err", err)
		return err
	}
	xlog.Info("passwordless login email sent", "email", req.Email)
	return nil
}

// PasswordlessLogin completes the passwordless login flow.
func (a *Auth) PasswordlessLogin(ctx context.Context, tokenValue string) (*TokenResponse, error) {
	xlog.Debug("processing passwordless login")
	token, err := a.Repo.TokenGetByToken(ctx, tokenValue)
	if err != nil {
		xlog.Debug("passwordless token not found", "err", err)
		return nil, errors.New("invalid or expired magic link")
	}

	if token.TokenType != models.TokenTypePasswordless {
		xlog.Warn("invalid token type for passwordless login", "type", token.TokenType)
		return nil, errors.New("invalid token type")
	}

	if time.Now().After(token.ExpiresAt) || token.Revoked {
		a.Repo.TokenRevoke(ctx, token.ID)
		xlog.Debug("passwordless token expired or revoked", "token_id", token.ID)
		return nil, errors.New("magic link expired")
	}

	user, err := a.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		xlog.Error("failed to get user for passwordless login", "user_id", token.UserID, "err", err)
		return nil, err
	}

	if !user.EmailVerified {
		now := time.Now()
		user.EmailVerified = true
		user.EmailVerifiedAt = &now
		if _, err := a.Repo.UserUpdate(ctx, user); err != nil {
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

// TokenCreate creates a new pair of access and refresh tokens for the given user.
func (a *Auth) TokenCreate(ctx context.Context, user *models.User) (*TokenResponse, error) {
	return a.tokenCreateForActor(ctx, user, "")
}

// tokenCreateForActor creates a new pair of access and refresh tokens for the given user.
// When actorID is non-empty, the access token carries an "act" claim identifying the
// acting user (e.g. an admin impersonating user), and the persisted refresh token is
// tagged in Metadata so it can be recognized and revoked as an impersonation token.
func (a *Auth) tokenCreateForActor(ctx context.Context, user *models.User, actorID string) (*TokenResponse, error) {
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

	metadata := models.JSONMap{}
	if actorID != "" {
		metadata["impersonation"] = true
		metadata["actor_id"] = actorID
	}

	now := time.Now()
	token := &models.Token{
		UserID:    user.ID,
		Token:     refreshToken,
		TokenType: models.TokenTypeRefresh,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
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
// calling this method.
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
	return a.tokenCreateForActor(ctx, target, adminUser.ID)
}

// StopImpersonating revokes an impersonation refresh token, ending that impersonation
// session server-side.
func (a *Auth) StopImpersonating(ctx context.Context, impersonationRefreshToken string) error {
	token, err := a.Repo.TokenGetByToken(ctx, impersonationRefreshToken)
	if err != nil {
		xlog.Debug("stop impersonation failed: token not found", "err", err)
		return errors.New("invalid impersonation token")
	}
	if imp, _ := token.Metadata["impersonation"].(bool); !imp {
		return errors.New("not an impersonation token")
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
	token, err := a.Repo.TokenGetByToken(ctx, refreshToken)
	if err != nil {
		xlog.Debug("refresh token not found", "err", err)
		return nil, errors.New("invalid refresh token")
	}

	if token.Revoked {
		xlog.Warn("attempt to use revoked token", "token_id", token.ID, "user_id", token.UserID)
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
	return a.tokenCreateForActor(ctx, user, actorID)
}

// TokenRevoke revokes the given refresh token.
func (a *Auth) TokenRevoke(ctx context.Context, refreshToken string) error {
	xlog.Info("revoking token")
	token, err := a.Repo.TokenGetByToken(ctx, refreshToken)
	if err != nil {
		xlog.Debug("token to revoke not found", "err", err)
		return err
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
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(a.Cfg.JWTSecret))
	return t, exp, err
}

func (a *Auth) generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
