package service

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/gopkg/xlog"
)

// jwtKeys holds the parsed signing/verification key material for access
// tokens, derived once from Cfg.JWT (or Cfg.JWTSecret for the default HS256
// mode) at Auth construction time.
type jwtKeys struct {
	method     jwt.SigningMethod
	signingKey any // []byte (HS256), *rsa.PrivateKey (RS256), or ed25519.PrivateKey (EdDSA)
	keyID      string

	// verifyByKeyID resolves a verification key by the token's "kid" header.
	// HS256 has a single entry under "" (HS256 tokens carry no kid). During
	// asymmetric key rotation this holds both the current and previous
	// public key, so tokens signed before the rotation keep verifying.
	verifyByKeyID map[string]any
}

// newJWTKeys parses cfg.JWT (falling back to HS256/cfg.JWTSecret when
// cfg.JWT.Algorithm is unset) into the key material generateAccessToken and
// AuthMiddleware need.
func newJWTKeys(cfg *config.Config) (*jwtKeys, error) {
	algo := cfg.JWT.Algorithm
	if algo == "" {
		algo = "HS256"
	}

	switch algo {
	case "HS256":
		if cfg.JWTSecret == "" {
			return nil, errors.New("JWT_SECRET is required for HS256 signing")
		}
		secret := []byte(cfg.JWTSecret)
		return &jwtKeys{
			method:        jwt.SigningMethodHS256,
			signingKey:    secret,
			verifyByKeyID: map[string]any{"": secret},
		}, nil

	case "RS256":
		return newAsymmetricJWTKeys(jwt.SigningMethodRS256, cfg.JWT,
			func(b []byte) (any, error) { return jwt.ParseRSAPrivateKeyFromPEM(b) },
			func(b []byte) (any, error) { return jwt.ParseRSAPublicKeyFromPEM(b) },
		)

	case "EdDSA":
		return newAsymmetricJWTKeys(jwt.SigningMethodEdDSA, cfg.JWT,
			func(b []byte) (any, error) { return jwt.ParseEdPrivateKeyFromPEM(b) },
			func(b []byte) (any, error) { return jwt.ParseEdPublicKeyFromPEM(b) },
		)

	default:
		return nil, fmt.Errorf("unsupported JWT_ALGORITHM %q: must be HS256, RS256, or EdDSA", algo)
	}
}

func newAsymmetricJWTKeys(
	method jwt.SigningMethod,
	jcfg config.JWT,
	parsePrivate func([]byte) (any, error),
	parsePublic func([]byte) (any, error),
) (*jwtKeys, error) {
	if jcfg.PrivateKey == "" || jcfg.PublicKey == "" {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required for %s signing", method.Alg())
	}

	priv, err := parsePrivate([]byte(jcfg.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_PRIVATE_KEY: %w", err)
	}
	pub, err := parsePublic([]byte(jcfg.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_PUBLIC_KEY: %w", err)
	}

	keys := &jwtKeys{
		method:        method,
		signingKey:    priv,
		keyID:         jwtKeyID(jcfg.KeyID, jcfg.PublicKey),
		verifyByKeyID: map[string]any{},
	}
	keys.verifyByKeyID[keys.keyID] = pub

	if jcfg.PreviousPublicKey != "" {
		prevPub, err := parsePublic([]byte(jcfg.PreviousPublicKey))
		if err != nil {
			return nil, fmt.Errorf("invalid JWT_PREVIOUS_PUBLIC_KEY: %w", err)
		}
		keys.verifyByKeyID[jwtKeyID(jcfg.PreviousKeyID, jcfg.PreviousPublicKey)] = prevPub
	}

	return keys, nil
}

// jwtKeyID returns explicit if set, otherwise a short, stable digest of the
// PEM-encoded public key — deterministic across restarts without needing
// the operator to invent/track a key ID themselves.
func jwtKeyID(explicit, publicKeyPEM string) string {
	if explicit != "" {
		return explicit
	}
	sum := sha256.Sum256([]byte(publicKeyPEM))
	return hex.EncodeToString(sum[:])[:16]
}

// JWTKeyFunc returns the jwt.Keyfunc AuthMiddleware uses to verify access
// tokens, resolving the key by the token's "kid" header (the sole entry
// under "" for HS256, which carries no kid).
func (a *Auth) JWTKeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		key, ok := a.jwtKeys.verifyByKeyID[kid]
		if !ok {
			return nil, fmt.Errorf("unknown key id %q", kid)
		}
		return key, nil
	}
}

// JWTSigningMethods returns the accepted access-token signing algorithm(s)
// for AuthMiddleware's jwt.WithValidMethods, guarding against algorithm
// confusion attacks (e.g. an attacker presenting an HS256 token signed with
// a known-public RS256 public key as the "secret").
func (a *Auth) JWTSigningMethods() []string {
	return []string{a.jwtKeys.method.Alg()}
}

// JWK is a single JSON Web Key (RFC 7517), covering the RSA and Ed25519
// (OKP) key types ezauth can sign with.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// OKP (Ed25519)
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

// JWKSet is a JSON Web Key Set (RFC 7517) — the response shape for
// /.well-known/jwks.json.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKS returns the JSON Web Key Set for the current (and, during a
// rotation, previous) asymmetric access-token signing key. Returns an
// empty set for the default HS256 mode — there is no public key to
// publish, and the shared secret must never be exposed here.
func (a *Auth) JWKS() JWKSet {
	set := JWKSet{Keys: []JWK{}}
	if a.jwtKeys.method == jwt.SigningMethodHS256 {
		return set
	}
	for kid, key := range a.jwtKeys.verifyByKeyID {
		jwk, err := toJWK(kid, a.jwtKeys.method.Alg(), key)
		if err != nil {
			xlog.Error("failed to encode JWK", "kid", kid, "err", err)
			continue
		}
		set.Keys = append(set.Keys, jwk)
	}
	return set
}

func toJWK(kid, alg string, key any) (JWK, error) {
	switch pub := key.(type) {
	case *rsa.PublicKey:
		return JWK{
			Kty: "RSA", Use: "sig", Alg: alg, Kid: kid,
			N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}, nil
	case ed25519.PublicKey:
		return JWK{
			Kty: "OKP", Use: "sig", Alg: alg, Kid: kid,
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
		}, nil
	default:
		return JWK{}, fmt.Errorf("unsupported public key type %T", key)
	}
}
