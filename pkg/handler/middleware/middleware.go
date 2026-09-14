package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

// Common errors are now in errors.go

type contextKey string

const (
	UserContextKey          = contextKey("userID")
	UserObjectContextKey    = contextKey("user")
	ImpersonatorContextKey  = contextKey("impersonatorID")
	SessionTokensContextKey = contextKey("sessionTokens")
	SessionImpersonatorKey  = contextKey("sessionImpersonatorID")
	APIKeyScopesContextKey  = contextKey("apiKeyScopes")
	OrgContextKey           = contextKey("orgID")
	OrgObjectContextKey     = contextKey("org")
)

// UserLoader is a function that loads a user from context.
type UserLoader func(context.Context) (*models.User, error)

// OrgLoader is a function that resolves the "current organization" for a
// request. ezauth doesn't presume how an org is identified (URL param,
// subdomain, header, etc.) — the consuming app supplies this, same as
// UserLoader doesn't presume how a user is resolved.
type OrgLoader func(context.Context) (*models.Organization, error)

// AuthMiddleware is a middleware that authenticates requests using a JWT bearer token.
// keyFunc resolves the verification key for a token (see jwt.Keyfunc — e.g. by its
// "kid" header, to support asymmetric key rotation); validMethods restricts which
// signing algorithms are accepted (e.g. []string{"HS256"} or []string{"RS256"}),
// guarding against algorithm-confusion attacks. userRepo re-checks the
// token's subject on every request: a valid signature and unexpired claims
// only prove the token was genuinely issued, not that the account is still
// active -- without this, a suspended/disabled/deleted user keeps Bearer
// access until the access token's own natural expiry. extraOpts are appended
// to the parser's own options -- e.g. jwt.WithIssuer/jwt.WithAudience, to
// additionally constrain which service a token was minted for when
// Cfg.JWT.Issuer/Audience are configured (see #207); omit for no additional
// constraints, matching every prior release's behavior.
func AuthMiddleware(keyFunc jwt.Keyfunc, validMethods []string, userRepo UserActiveGetter, extraOpts ...jwt.ParserOption) func(http.Handler) http.Handler {
	parserOpts := append([]jwt.ParserOption{jwt.WithValidMethods(validMethods)}, extraOpts...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrAuthorizationHeaderRequired)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrBearerTokenRequired)
				return
			}

			token, err := jwt.Parse(tokenString, keyFunc, parserOpts...)

			if err != nil {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidToken)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok || !token.Valid {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidToken)
				return
			}

			userID, ok := claims["sub"].(string)
			if !ok {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidTokenClaims)
				return
			}

			user, err := userRepo.UserGetByID(r.Context(), userID)
			if err != nil || !user.IsActive {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidToken)
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, userID)
			if act, ok := claims["act"].(map[string]any); ok {
				if actorID, ok := act["sub"].(string); ok && actorID != "" {
					ctx = context.WithValue(ctx, ImpersonatorContextKey, actorID)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// APIKeyMiddleware checks for a valid API key in the X-API-Key header.
// userRepo re-checks the key owner's status on every request: a DB-backed
// key's own type/revoked/expiry fields say nothing about whether the
// account it belongs to is still active, so without this a suspended user's
// still-valid API key keeps working indefinitely. Not applicable to the
// shared config master key (configApiKey), which has no owning user.
func APIKeyMiddleware(configApiKey string, tokenRepo TokenGetter, userRepo UserActiveGetter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrAPIKeyRequired)
				return
			}

			// Check against config first (constant-time comparison)
			if subtle.ConstantTimeCompare([]byte(apiKey), []byte(configApiKey)) == 1 {
				// The master config key has no associated Token/scopes at
				// all -- explicitly record "authenticated, unscoped" so
				// RequireAPIKeyScope can tell it apart from a request that
				// never went through this middleware.
				ctx := context.WithValue(r.Context(), APIKeyScopesContextKey, []string{})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Check against database. Stored/looked-up by hash, not the raw
			// key (see util.HashToken) -- a DB-read compromise shouldn't
			// hand over directly usable API keys.
			token, err := tokenRepo.TokenGetByToken(r.Context(), util.HashToken(apiKey))
			if err != nil {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidAPIKey)
				return
			}

			if token.TokenType != models.TokenTypeApiKey {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidAPIKey)
				return
			}

			if token.Revoked {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidAPIKey)
				return
			}

			if !token.ExpiresAt.IsZero() && token.ExpiresAt.Before(time.Now()) {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidAPIKey)
				return
			}

			user, err := userRepo.UserGetByID(r.Context(), token.UserID)
			if err != nil || !user.IsActive {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidAPIKey)
				return
			}

			ctx := context.WithValue(r.Context(), APIKeyScopesContextKey, token.Scopes())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAPIKeyScope is a middleware that requires the API key used to
// authenticate the request (via APIKeyMiddleware, which MUST run upstream --
// on every dialect of success, including the master config key, it sets
// APIKeyScopesContextKey) to include the given scope.
//
// A missing context value means APIKeyMiddleware never ran on this route at
// all (e.g. a custom router wired without it) -- there is no authentication
// on the request whatsoever, so this rejects with 401 rather than failing
// open.
//
// WARNING: an unscoped key — one created with a nil/empty scopes list, any
// key issued before per-key scoping existed, or the master config API key —
// passes this check unconditionally once authenticated. "No scopes" means
// "full access", not "no access". This is intentional for backward
// compatibility (every key predating scoping must keep working), but it's a
// footgun: a key created without an explicit scopes list is NOT a restricted
// key. Always pass a non-empty scopes list for any key that should be
// limited; see the "Scoped API Keys" section of the README for the full
// explanation.
func RequireAPIKeyScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scopes, ok := r.Context().Value(APIKeyScopesContextKey).([]string)
			if !ok {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrAPIKeyRequired)
				return
			}
			if len(scopes) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			for _, s := range scopes {
				if s == scope {
					next.ServeHTTP(w, r)
					return
				}
			}
			WriteJSONResponseError(w, http.StatusForbidden, ErrForbidden)
		})
	}
}

// RoleChecker defines the interface for checking whether a user holds a role,
// backed by the RBAC roles/permissions tables (not the legacy comma-string
// User.Roles field).
type RoleChecker interface {
	UserHasRole(ctx context.Context, userID, role string) (bool, error)
}

// PermissionChecker defines the interface for checking whether a user holds
// a permission, backed by the RBAC roles/permissions tables.
type PermissionChecker interface {
	UserHasPermission(ctx context.Context, userID, permission string) (bool, error)
}

// RequireRole is a middleware that requires the authenticated user (identified
// via UserContextKey, set by AuthMiddleware or LoadUserMiddleware — this
// middleware must run downstream of one of those) to hold the given role.
func RequireRole(checker RoleChecker, role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := r.Context().Value(UserContextKey).(string)
			if !ok || userID == "" {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
				return
			}
			has, err := checker.UserHasRole(r.Context(), userID, role)
			if err != nil || !has {
				WriteJSONResponseError(w, http.StatusForbidden, ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission is a middleware that requires the authenticated user
// (identified via UserContextKey, set by AuthMiddleware or LoadUserMiddleware
// — this middleware must run downstream of one of those) to hold the given
// permission.
func RequirePermission(checker PermissionChecker, permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := r.Context().Value(UserContextKey).(string)
			if !ok || userID == "" {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
				return
			}
			has, err := checker.UserHasPermission(r.Context(), userID, permission)
			if err != nil || !has {
				WriteJSONResponseError(w, http.StatusForbidden, ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// OrgMembershipChecker defines the interface for checking a user's role
// within a specific organization, backed by the org_members table.
type OrgMembershipChecker interface {
	OrgMemberRole(ctx context.Context, orgID, userID string) (roleName string, isMember bool, err error)
}

// RequireOrgMembership is a middleware that requires the authenticated user
// (UserContextKey, set by AuthMiddleware or LoadUserMiddleware) to be a
// member -- of any role -- of the "current organization" (OrgContextKey,
// set by OrgLoaderMiddleware). Both of those middlewares must run upstream.
//
// ezauth's own org service methods (pkg/service/org.go) perform no
// membership check themselves, matching the rest of this package's RBAC
// methods, which rely entirely on the HTTP-gate layer for authorization
// (see #204) -- so mount this (or RequireOrgRole) on organization routes
// yourself if you've customized WithAdminAuthz to something other than the
// default blanket global-admin gate, and want per-organization scoping
// instead of (or in addition to) it.
func RequireOrgMembership(checker OrgMembershipChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := r.Context().Value(UserContextKey).(string)
			if !ok || userID == "" {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
				return
			}
			orgID, ok := r.Context().Value(OrgContextKey).(string)
			if !ok || orgID == "" {
				WriteJSONResponseError(w, http.StatusForbidden, ErrForbidden)
				return
			}
			_, isMember, err := checker.OrgMemberRole(r.Context(), orgID, userID)
			if err != nil || !isMember {
				WriteJSONResponseError(w, http.StatusForbidden, ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireOrgRole is like RequireOrgMembership, additionally requiring the
// caller's membership role within the current organization to equal role.
func RequireOrgRole(checker OrgMembershipChecker, role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := r.Context().Value(UserContextKey).(string)
			if !ok || userID == "" {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
				return
			}
			orgID, ok := r.Context().Value(OrgContextKey).(string)
			if !ok || orgID == "" {
				WriteJSONResponseError(w, http.StatusForbidden, ErrForbidden)
				return
			}
			roleName, isMember, err := checker.OrgMemberRole(r.Context(), orgID, userID)
			if err != nil || !isMember || roleName != role {
				WriteJSONResponseError(w, http.StatusForbidden, ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// LoginRequiredMiddleware is a middleware that requires the request to be authenticated.
func LoginRequiredMiddleware(authChecker AuthChecker, loginPath string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !authChecker.IsAuthenticated(r.Context()) {
				// Distinguish an API request (JSON) from a browser request by
				// content negotiation alone -- this middleware is exported for
				// use on a consuming application's own routes, which may be
				// mounted at any path, so a hardcoded URL prefix (e.g.
				// "/auth/api", ezauth's own JSON API) can't reliably identify
				// an API request there.
				if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.Contains(r.Header.Get("Content-Type"), "application/json") {
					WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
					return
				}

				// redirect to login
				http.Redirect(w, r, loginPath, http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// LoadUserMiddleware is a middleware that loads the authenticated user into the context.
func LoadUserMiddleware(loader UserLoader) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if user, err := loader(ctx); err == nil {
				ctx = context.WithValue(ctx, UserContextKey, user.ID)
				ctx = context.WithValue(ctx, UserObjectContextKey, user)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OrgLoaderMiddleware is a middleware that resolves the "current organization"
// for a request (via loader) and loads it into the context. Downstream
// handlers read it with GetSessionOrg. Mirrors LoadUserMiddleware exactly.
func OrgLoaderMiddleware(loader OrgLoader) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if org, err := loader(ctx); err == nil {
				ctx = context.WithValue(ctx, OrgContextKey, org.ID)
				ctx = context.WithValue(ctx, OrgObjectContextKey, org)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LoadAndSaveMiddleware uses the session manager
func LoadAndSaveMiddleware(sm *scs.SessionManager) func(http.Handler) http.Handler {
	return sm.LoadAndSave
}

// SessionMiddleware combines LoadAndSaveMiddleware and LoadUserMiddleware
func SessionMiddleware(sm *scs.SessionManager, loader UserLoader) func(http.Handler) http.Handler {
	return Chain(LoadAndSaveMiddleware(sm), LoadUserMiddleware(loader))
}

// Chain applies middlewares in order
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// MaxBodyBytes caps request bodies at limit bytes using http.MaxBytesReader,
// so a client can't exhaust server memory/bandwidth with an oversized
// payload. A handler's json.Decode (or similar) will fail with an error once
// the limit is exceeded, same as any other malformed-body error.
func MaxBodyBytes(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}
