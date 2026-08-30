package service

import (
	"context"
	"errors"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
)

// ErrTrustedDeviceNotFound is returned when a trusted device token/record
// doesn't exist, doesn't belong to the caller, or isn't a trusted device.
var ErrTrustedDeviceNotFound = errors.New("trusted device not found")

// TrustDevice issues a new trusted-device token for user, valid for
// Cfg.TrustedDevice.TTL. While a valid token is presented to CompleteBasicLogin,
// TOTP MFA step-up is skipped for that device. name is an optional
// caller-supplied label (e.g. a User-Agent-derived description).
func (a *Auth) TrustDevice(ctx context.Context, user *models.User, name string) (string, error) {
	deviceToken, err := a.generateRefreshToken()
	if err != nil {
		return "", err
	}

	token := &models.Token{
		UserID:    user.ID,
		Token:     deviceToken,
		TokenType: models.TokenTypeTrustedDevice,
		ExpiresAt: time.Now().Add(a.Cfg.TrustedDevice.TTL),
		CreatedAt: time.Now(),
		Metadata:  models.JSONMap{"name": name},
	}
	if _, err := a.Repo.TokenCreate(ctx, token); err != nil {
		xlog.Error("failed to save trusted device token", "user_id", user.ID, "err", err)
		return "", err
	}
	xlog.Info("device trusted", "user_id", user.ID)
	return deviceToken, nil
}

// IsTrustedDevice reports whether deviceToken is a valid, unexpired trusted
// device token belonging to user. A blank deviceToken is never trusted.
func (a *Auth) IsTrustedDevice(ctx context.Context, user *models.User, deviceToken string) bool {
	if deviceToken == "" {
		return false
	}
	tok, err := a.Repo.TokenGetByToken(ctx, deviceToken)
	if err != nil {
		return false
	}
	if tok.TokenType != models.TokenTypeTrustedDevice || tok.UserID != user.ID {
		return false
	}
	if tok.Revoked || time.Now().After(tok.ExpiresAt) {
		return false
	}
	return true
}

// TrustedDeviceInfo describes a trusted device without exposing its raw token value.
type TrustedDeviceInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TrustedDevices lists the trusted devices registered for a user.
func (a *Auth) TrustedDevices(ctx context.Context, userID string) ([]TrustedDeviceInfo, error) {
	tokens, err := a.Repo.TokenListByUserIDAndType(ctx, userID, models.TokenTypeTrustedDevice)
	if err != nil {
		return nil, err
	}

	devices := make([]TrustedDeviceInfo, 0, len(tokens))
	for _, tok := range tokens {
		name, _ := tok.Metadata["name"].(string)
		devices = append(devices, TrustedDeviceInfo{
			ID:        tok.ID,
			Name:      name,
			CreatedAt: tok.CreatedAt,
			ExpiresAt: tok.ExpiresAt,
		})
	}
	return devices, nil
}

// RevokeTrustedDevice revokes one of user's trusted devices by its record ID
// (as returned by TrustedDevices), un-trusting it immediately.
func (a *Auth) RevokeTrustedDevice(ctx context.Context, user *models.User, deviceID string) error {
	tok, err := a.Repo.TokenGetByID(ctx, deviceID)
	if err != nil || tok.UserID != user.ID || tok.TokenType != models.TokenTypeTrustedDevice {
		return ErrTrustedDeviceNotFound
	}
	if err := a.Repo.TokenRevoke(ctx, tok.ID); err != nil {
		xlog.Error("failed to revoke trusted device", "device_id", tok.ID, "err", err)
		return err
	}
	xlog.Info("trusted device revoked", "user_id", user.ID, "device_id", tok.ID)
	return nil
}
