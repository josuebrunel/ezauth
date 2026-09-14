package middleware

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
)

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
