package middleware

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/josuebrunel/gopkg/xlog"
)

// genericServerErrorMessage is returned to clients in place of the real
// error text for 5xx responses, since that text may come straight from the
// DB/repository layer and leak internal schema/query details. The real
// error is still logged server-side via xlog.Error.
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
