package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/models"
)

func generateRSAKeyPair(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal RSA private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

func generateEdKeyPair(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal Ed25519 private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to marshal Ed25519 public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

func TestNewJWTKeys_HS256Default(t *testing.T) {
	keys, err := newJWTKeys(&config.Config{JWTSecret: "test-secret-0123456789-0123456789"})
	if err != nil {
		t.Fatalf("newJWTKeys failed: %v", err)
	}
	if keys.method.Alg() != "HS256" {
		t.Errorf("expected HS256, got %s", keys.method.Alg())
	}
	if keys.keyID != "" {
		t.Errorf("expected no kid for HS256, got %q", keys.keyID)
	}
}

func TestNewJWTKeys_MissingSecret(t *testing.T) {
	if _, err := newJWTKeys(&config.Config{}); err == nil {
		t.Fatal("expected error for missing JWTSecret under default HS256")
	}
}

// TestNewJWTKeys_ShortSecretRejected proves the config.MinJWTSecretLength
// floor is enforced here too, not just in config.LoadConfig -- a hand-built
// config.Config{} (tests, or a library consumer constructing one directly)
// bypasses LoadConfig entirely, and previously got a brute-forceable HS256
// key with no error.
func TestNewJWTKeys_ShortSecretRejected(t *testing.T) {
	short := strings.Repeat("a", config.MinJWTSecretLength-1)
	if _, err := newJWTKeys(&config.Config{JWTSecret: short}); err == nil {
		t.Fatalf("expected error for a %d-char secret (floor is %d)", len(short), config.MinJWTSecretLength)
	}

	exact := strings.Repeat("a", config.MinJWTSecretLength)
	if _, err := newJWTKeys(&config.Config{JWTSecret: exact}); err != nil {
		t.Fatalf("expected a %d-char secret (exactly the floor) to be accepted: %v", len(exact), err)
	}
}

func TestNewJWTKeys_UnsupportedAlgorithm(t *testing.T) {
	_, err := newJWTKeys(&config.Config{JWT: config.JWT{Algorithm: "ES256"}})
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestNewJWTKeys_AsymmetricMissingKeys(t *testing.T) {
	for _, algo := range []string{"RS256", "EdDSA"} {
		if _, err := newJWTKeys(&config.Config{JWT: config.JWT{Algorithm: algo}}); err == nil {
			t.Errorf("%s: expected error when PrivateKey/PublicKey are unset", algo)
		}
	}
}

func TestNewJWTKeys_AsymmetricInvalidPEM(t *testing.T) {
	_, err := newJWTKeys(&config.Config{JWT: config.JWT{
		Algorithm:  "RS256",
		PrivateKey: "not-a-pem-key",
		PublicKey:  "not-a-pem-key",
	}})
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestAuth_AsymmetricSigningAndVerification(t *testing.T) {
	rsaPriv, rsaPub := generateRSAKeyPair(t)
	edPriv, edPub := generateEdKeyPair(t)

	cases := []struct {
		name string
		algo string
		priv string
		pub  string
	}{
		{"RS256", "RS256", rsaPriv, rsaPub},
		{"EdDSA", "EdDSA", edPriv, edPub},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth, err := New(&config.Config{
				JWTSecret: "unused-for-asymmetric",
				JWT:       config.JWT{Algorithm: tc.algo, PrivateKey: tc.priv, PublicKey: tc.pub},
			}, nil, "auth")
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}

			user := &models.User{ID: "user-1", Email: "user1@example.com"}
			tokenString, _, err := auth.generateAccessToken(user, "")
			if err != nil {
				t.Fatalf("generateAccessToken failed: %v", err)
			}

			// Round-trip through the same key resolution/validation AuthMiddleware uses.
			parsed, err := jwt.Parse(tokenString, auth.JWTKeyFunc(), jwt.WithValidMethods(auth.JWTSigningMethods()))
			if err != nil {
				t.Fatalf("failed to verify %s-signed token: %v", tc.algo, err)
			}
			claims, ok := parsed.Claims.(jwt.MapClaims)
			if !ok || claims["sub"] != user.ID {
				t.Errorf("expected sub %s, got %v", user.ID, claims["sub"])
			}
			if kid, _ := parsed.Header["kid"].(string); kid == "" {
				t.Error("expected a non-empty kid header for asymmetric signing")
			}

			// JWKS publishes exactly the signing public key.
			set := auth.JWKS()
			if len(set.Keys) != 1 {
				t.Fatalf("expected 1 JWK, got %d", len(set.Keys))
			}
			if set.Keys[0].Alg != tc.algo {
				t.Errorf("expected alg %s, got %s", tc.algo, set.Keys[0].Alg)
			}
			if set.Keys[0].Kid != auth.jwtKeys.keyID {
				t.Errorf("expected kid %s, got %s", auth.jwtKeys.keyID, set.Keys[0].Kid)
			}
		})
	}
}

func TestJWKS_EmptyForHS256(t *testing.T) {
	auth, err := New(&config.Config{JWTSecret: "test-secret-0123456789-0123456789"}, nil, "auth")
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	set := auth.JWKS()
	if len(set.Keys) != 0 {
		t.Errorf("expected no published keys for HS256, got %d", len(set.Keys))
	}
}

func TestJWTKeyID(t *testing.T) {
	_, pub := generateRSAKeyPair(t)

	if got := jwtKeyID("explicit-kid", pub); got != "explicit-kid" {
		t.Errorf("expected explicit kid to win, got %q", got)
	}

	kid1 := jwtKeyID("", pub)
	kid2 := jwtKeyID("", pub)
	if kid1 == "" {
		t.Fatal("expected a derived kid")
	}
	if kid1 != kid2 {
		t.Errorf("expected derived kid to be deterministic, got %q and %q", kid1, kid2)
	}

	_, otherPub := generateRSAKeyPair(t)
	if jwtKeyID("", otherPub) == kid1 {
		t.Error("expected different public keys to derive different kids")
	}
}

func TestAuth_KeyRotation(t *testing.T) {
	oldPriv, oldPub := generateRSAKeyPair(t)
	newPriv, newPub := generateRSAKeyPair(t)

	// Sign a token under the "old" key, simulating one issued before rotation.
	oldAuth, err := New(&config.Config{
		JWTSecret: "unused",
		JWT:       config.JWT{Algorithm: "RS256", PrivateKey: oldPriv, PublicKey: oldPub, KeyID: "old-kid"},
	}, nil, "auth")
	if err != nil {
		t.Fatalf("New (old) failed: %v", err)
	}
	oldUser := &models.User{ID: "user-1", Email: "user1@example.com"}
	oldTokenString, _, err := oldAuth.generateAccessToken(oldUser, "")
	if err != nil {
		t.Fatalf("generateAccessToken (old) failed: %v", err)
	}

	// Rotate: now sign with the "new" key, but keep the old public key around
	// for verification so the pre-rotation token issued above still validates.
	rotatedAuth, err := New(&config.Config{
		JWTSecret: "unused",
		JWT: config.JWT{
			Algorithm: "RS256", PrivateKey: newPriv, PublicKey: newPub, KeyID: "new-kid",
			PreviousPublicKey: oldPub, PreviousKeyID: "old-kid",
		},
	}, nil, "auth")
	if err != nil {
		t.Fatalf("New (rotated) failed: %v", err)
	}

	t.Run("new tokens sign under the new key", func(t *testing.T) {
		tokenString, _, err := rotatedAuth.generateAccessToken(oldUser, "")
		if err != nil {
			t.Fatalf("generateAccessToken failed: %v", err)
		}
		parsed, err := jwt.Parse(tokenString, rotatedAuth.JWTKeyFunc(), jwt.WithValidMethods(rotatedAuth.JWTSigningMethods()))
		if err != nil {
			t.Fatalf("failed to verify newly signed token: %v", err)
		}
		if kid, _ := parsed.Header["kid"].(string); kid != "new-kid" {
			t.Errorf("expected kid new-kid, got %q", kid)
		}
	})

	t.Run("pre-rotation tokens still verify", func(t *testing.T) {
		parsed, err := jwt.Parse(oldTokenString, rotatedAuth.JWTKeyFunc(), jwt.WithValidMethods(rotatedAuth.JWTSigningMethods()))
		if err != nil {
			t.Fatalf("expected pre-rotation token to still verify, got: %v", err)
		}
		if !parsed.Valid {
			t.Error("expected pre-rotation token to be valid")
		}
	})

	t.Run("JWKS publishes both keys during the rotation window", func(t *testing.T) {
		set := rotatedAuth.JWKS()
		if len(set.Keys) != 2 {
			t.Fatalf("expected 2 published keys during rotation, got %d", len(set.Keys))
		}
		var kids []string
		for _, k := range set.Keys {
			kids = append(kids, k.Kid)
		}
		if !strings.Contains(strings.Join(kids, ","), "new-kid") || !strings.Contains(strings.Join(kids, ","), "old-kid") {
			t.Errorf("expected both old-kid and new-kid published, got %v", kids)
		}
	})
}

func TestAuth_RejectsWrongAlgorithm(t *testing.T) {
	hsAuth, err := New(&config.Config{JWTSecret: "test-secret-0123456789-0123456789"}, nil, "auth")
	if err != nil {
		t.Fatalf("New (HS256) failed: %v", err)
	}
	user := &models.User{ID: "user-1", Email: "user1@example.com"}
	hsToken, _, err := hsAuth.generateAccessToken(user, "")
	if err != nil {
		t.Fatalf("generateAccessToken failed: %v", err)
	}

	rsaPriv, rsaPub := generateRSAKeyPair(t)
	rsAuth, err := New(&config.Config{
		JWTSecret: "unused",
		JWT:       config.JWT{Algorithm: "RS256", PrivateKey: rsaPriv, PublicKey: rsaPub},
	}, nil, "auth")
	if err != nil {
		t.Fatalf("New (RS256) failed: %v", err)
	}

	if _, err := jwt.Parse(hsToken, rsAuth.JWTKeyFunc(), jwt.WithValidMethods(rsAuth.JWTSigningMethods())); err == nil {
		t.Fatal("expected an HS256-signed token to be rejected by an RS256-configured verifier")
	}
}

// TestGenerateAccessToken_Claims proves access tokens carry a jti (needed
// for any future denylist-based revocation -- structurally impossible
// without one), and iss/aud only when Cfg.JWT.Issuer/Audience are
// configured -- an unconfigured deployment sees no new claims at all,
// preserving prior-release token shape. See #207.
func TestGenerateAccessToken_Claims(t *testing.T) {
	claimsOf := func(t *testing.T, auth *Auth, tokenString string) jwt.MapClaims {
		t.Helper()
		parsed, err := jwt.Parse(tokenString, auth.JWTKeyFunc(), jwt.WithValidMethods(auth.JWTSigningMethods()))
		if err != nil {
			t.Fatalf("failed to parse generated token: %v", err)
		}
		claims, ok := parsed.Claims.(jwt.MapClaims)
		if !ok {
			t.Fatal("expected jwt.MapClaims")
		}
		return claims
	}
	user := &models.User{ID: "user-1", Email: "user1@example.com"}

	t.Run("jti present, iss/aud absent when unconfigured", func(t *testing.T) {
		auth, err := New(&config.Config{JWTSecret: "test-secret-0123456789-0123456789"}, nil, "auth")
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		tokenString, _, err := auth.generateAccessToken(user, "")
		if err != nil {
			t.Fatalf("generateAccessToken failed: %v", err)
		}
		claims := claimsOf(t, auth, tokenString)

		jti, _ := claims["jti"].(string)
		if jti == "" {
			t.Error("expected a non-empty jti claim")
		}
		if _, ok := claims["iss"]; ok {
			t.Error("expected no iss claim when Cfg.JWT.Issuer is unset")
		}
		if _, ok := claims["aud"]; ok {
			t.Error("expected no aud claim when Cfg.JWT.Audience is unset")
		}
	})

	t.Run("iss/aud present and distinct jti per token when configured", func(t *testing.T) {
		auth, err := New(&config.Config{
			JWTSecret: "test-secret-0123456789-0123456789",
			JWT:       config.JWT{Issuer: "https://auth.example.com", Audience: "example-api"},
		}, nil, "auth")
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		token1, _, err := auth.generateAccessToken(user, "")
		if err != nil {
			t.Fatalf("generateAccessToken failed: %v", err)
		}
		token2, _, err := auth.generateAccessToken(user, "")
		if err != nil {
			t.Fatalf("generateAccessToken failed: %v", err)
		}

		claims1 := claimsOf(t, auth, token1)
		claims2 := claimsOf(t, auth, token2)

		if claims1["iss"] != "https://auth.example.com" {
			t.Errorf("expected iss %q, got %v", "https://auth.example.com", claims1["iss"])
		}
		if claims1["aud"] != "example-api" {
			t.Errorf("expected aud %q, got %v", "example-api", claims1["aud"])
		}
		if claims1["jti"] == claims2["jti"] {
			t.Error("expected distinct jti values across separately-minted tokens")
		}
	})
}

// TestGenerateAccessToken_TTL proves Cfg.JWT.AccessTokenTTL controls the
// token's expiry, and a zero value (a hand-built config.Config{} bypassing
// LoadConfig's default:"15m" env tag) falls back to a sane default instead
// of minting a token that expires the instant it's issued.
func TestGenerateAccessToken_TTL(t *testing.T) {
	user := &models.User{ID: "user-1", Email: "user1@example.com"}

	t.Run("zero TTL falls back to defaultAccessTokenTTL", func(t *testing.T) {
		auth, err := New(&config.Config{JWTSecret: "test-secret-0123456789-0123456789"}, nil, "auth")
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		_, exp, err := auth.generateAccessToken(user, "")
		if err != nil {
			t.Fatalf("generateAccessToken failed: %v", err)
		}
		gotTTL := time.Until(exp)
		if gotTTL < defaultAccessTokenTTL-time.Minute || gotTTL > defaultAccessTokenTTL {
			t.Errorf("expected TTL close to the %v default, got %v", defaultAccessTokenTTL, gotTTL)
		}
	})

	t.Run("configured TTL is honored", func(t *testing.T) {
		auth, err := New(&config.Config{
			JWTSecret: "test-secret-0123456789-0123456789",
			JWT:       config.JWT{AccessTokenTTL: 5 * time.Minute},
		}, nil, "auth")
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		_, exp, err := auth.generateAccessToken(user, "")
		if err != nil {
			t.Fatalf("generateAccessToken failed: %v", err)
		}
		gotTTL := time.Until(exp)
		if gotTTL < 4*time.Minute || gotTTL > 5*time.Minute {
			t.Errorf("expected TTL close to the configured 5m, got %v", gotTTL)
		}
	})
}
