package service

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestTrustedDevice(t *testing.T) {
	auth := setupMFATestDB(t)
	ctx := context.Background()
	user := mfaTestUser(t, auth, ctx)

	enrollResp, err := auth.MFAEnroll(ctx, user)
	if err != nil {
		t.Fatalf("MFAEnroll failed: %v", err)
	}
	code, err := totp.GenerateCode(enrollResp.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate totp code: %v", err)
	}
	if _, err := auth.MFAConfirm(ctx, user, code); err != nil {
		t.Fatalf("MFAConfirm failed: %v", err)
	}

	var deviceToken string
	t.Run("login verify with remember_device issues a trusted device token", func(t *testing.T) {
		resp, err := auth.CompleteBasicLogin(ctx, user, "")
		if err != nil {
			t.Fatalf("CompleteBasicLogin failed: %v", err)
		}
		validCode, err := totp.GenerateCode(*user.MfaSecret, time.Now())
		if err != nil {
			t.Fatalf("failed to generate totp code: %v", err)
		}

		_, _, deviceToken, err = auth.MFALoginVerify(ctx, resp.MFAToken, validCode, true)
		if err != nil {
			t.Fatalf("MFALoginVerify failed: %v", err)
		}
		if deviceToken == "" {
			t.Fatal("expected a non-empty device token")
		}
	})

	t.Run("trusted device skips mfa step-up on next login", func(t *testing.T) {
		resp, err := auth.CompleteBasicLogin(ctx, user, deviceToken)
		if err != nil {
			t.Fatalf("CompleteBasicLogin failed: %v", err)
		}
		if resp.MFARequired || resp.TokenResponse == nil {
			t.Fatalf("expected direct tokens for trusted device, got %+v", resp)
		}
	})

	t.Run("device shows up in TrustedDevices", func(t *testing.T) {
		devices, err := auth.TrustedDevices(ctx, user.ID)
		if err != nil {
			t.Fatalf("TrustedDevices failed: %v", err)
		}
		if len(devices) != 1 {
			t.Fatalf("expected 1 trusted device, got %d", len(devices))
		}
	})

	t.Run("bogus device token does not skip mfa step-up", func(t *testing.T) {
		resp, err := auth.CompleteBasicLogin(ctx, user, "not-a-real-device-token")
		if err != nil {
			t.Fatalf("CompleteBasicLogin failed: %v", err)
		}
		if !resp.MFARequired {
			t.Fatal("expected mfa challenge for an unrecognized device token")
		}
	})

	t.Run("revoking the device makes it untrusted again", func(t *testing.T) {
		devices, err := auth.TrustedDevices(ctx, user.ID)
		if err != nil {
			t.Fatalf("TrustedDevices failed: %v", err)
		}
		if err := auth.RevokeTrustedDevice(ctx, user, devices[0].ID); err != nil {
			t.Fatalf("RevokeTrustedDevice failed: %v", err)
		}

		resp, err := auth.CompleteBasicLogin(ctx, user, deviceToken)
		if err != nil {
			t.Fatalf("CompleteBasicLogin failed: %v", err)
		}
		if !resp.MFARequired {
			t.Fatal("expected mfa challenge after revoking the trusted device")
		}

		devices, err = auth.TrustedDevices(ctx, user.ID)
		if err != nil {
			t.Fatalf("TrustedDevices failed: %v", err)
		}
		if len(devices) != 0 {
			t.Fatalf("expected no trusted devices after revoke, got %d", len(devices))
		}
	})

	t.Run("revoke rejects another user's device", func(t *testing.T) {
		other := mfaTestUser(t, auth, ctx)
		deviceToken, err := auth.TrustDevice(ctx, user, "some device")
		if err != nil {
			t.Fatalf("TrustDevice failed: %v", err)
		}
		devices, err := auth.TrustedDevices(ctx, user.ID)
		if err != nil {
			t.Fatalf("TrustedDevices failed: %v", err)
		}
		_ = deviceToken

		var deviceID string
		for _, d := range devices {
			deviceID = d.ID
		}
		if err := auth.RevokeTrustedDevice(ctx, other, deviceID); err != ErrTrustedDeviceNotFound {
			t.Fatalf("expected ErrTrustedDeviceNotFound, got %v", err)
		}
	})
}
