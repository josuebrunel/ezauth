package handler

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
)

// TestWriteJSONResponseError_ServerErrorsAreGeneric proves this package's
// own WriteJSONResponseError -- the one most JSON API handlers actually
// call (admin.go, email_change.go, sessions.go, org.go, rbac.go,
// invitation.go, ...) -- masks 5xx error text the same way
// middleware.WriteJSONResponseError does (see #142). Before #200, this
// copy had no such masking: a raw DB/repository error (schema details,
// driver-specific messages) went straight into both the "error" and
// "data" fields of the response regardless of status code.
func TestWriteJSONResponseError_ServerErrorsAreGeneric(t *testing.T) {
	dbErr := errors.New(`pq: duplicate key value violates unique constraint "users_email_key"`)

	w := httptest.NewRecorder()
	WriteJSONResponseError(w, 500, dbErr)

	var resp ApiResponse[string]
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error != genericServerErrorMessage {
		t.Fatalf("expected generic error message %q, got %q (leaked raw error)", genericServerErrorMessage, resp.Error)
	}
	if resp.Data != "" {
		t.Fatalf("expected empty Data field, got %q (leaked raw error)", resp.Data)
	}
}

func TestWriteJSONResponseError_ClientErrorsPassThrough(t *testing.T) {
	clientErr := errors.New("email is required")

	w := httptest.NewRecorder()
	WriteJSONResponseError(w, 400, clientErr)

	var resp ApiResponse[string]
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error != clientErr.Error() {
		t.Fatalf("expected client-facing message %q for a 4xx response, got %q", clientErr.Error(), resp.Error)
	}
}
