package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/josuebrunel/gopkg/xlog"
)

// genericServerErrorMessage is returned to clients in place of the real
// error text for 5xx responses, since that text may come straight from the
// DB/repository layer and leak internal schema/query details. The real
// error is still logged server-side via xlog.Error. Mirrors
// middleware/response.go's identical constant -- see WriteJSONResponse's
// doc comment for why this package doesn't just call that one directly.
const genericServerErrorMessage = "internal server error"

type ApiResponse[T any] struct {
	Error string `json:"error,omitempty"`
	Data  T      `json:"data,omitempty"`
}

func NewApiResponse[T any](data T, err error) *ApiResponse[T] {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	return &ApiResponse[T]{
		Data:  data,
		Error: errMsg,
	}
}

// WriteJSONResponse writes data/err as JSON. For a 5xx status, err's real
// text is replaced with a generic message in the response (it's still
// logged server-side via xlog.Error) -- it may come straight from the
// DB/repository layer and leak internal schema/query details otherwise.
//
// This duplicates middleware.WriteJSONResponse (which received the same
// fix first, under #142) rather than calling it directly: package handler
// predates that split and most of its ~90 call sites use the unqualified
// name, so porting the fix in place here is the lower-risk change. See #200.
func WriteJSONResponse[T any](w http.ResponseWriter, status int, data T, err error) {
	clientErr := err
	if err != nil {
		if status >= 500 {
			xlog.Error("request failed", "status", status, "err", err)
			clientErr = errors.New(genericServerErrorMessage)
		} else {
			xlog.Warn("request failed", "status", status, "err", err)
		}
	}

	resp := NewApiResponse(data, clientErr)
	d, e := json.Marshal(resp)
	if e != nil {
		xlog.Error("failed to marshal response", "err", e)
		http.Error(w, e.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(d)
}

func WriteJSONResponseError(w http.ResponseWriter, status int, err error) {
	// Data is left empty rather than duplicating err.Error() here: for 5xx
	// responses WriteJSONResponse substitutes a generic message in the
	// Error field, and echoing the raw error into Data would defeat that.
	WriteJSONResponse[string](w, status, "", err)
}

// capabilityTokenFromRequest reads a single-use capability token (e.g. an
// email-change or passwordless-login token) from the query string, or --
// for a POST -- from a "token" field in a JSON request body. Query-string
// support stays for backward compatibility (email/magic-link clients issue
// a plain GET when a link is clicked; that isn't going away), but embedding
// the token in a URL leaks it into access logs, browser history, and
// Referer headers, so POST-with-body is the safer option for any caller
// that isn't just following an emailed link. See #208.
func capabilityTokenFromRequest(r *http.Request) string {
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}
	if r.Method == http.MethodPost && r.ContentLength != 0 {
		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			return body.Token
		}
	}
	return ""
}
