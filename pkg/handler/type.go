package handler

import (
	"encoding/json"
	"net/http"

	"github.com/josuebrunel/gopkg/xlog"
)

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
	if err != nil {
		if status >= 500 {
			xlog.Error("request failed", "status", status, "err", err)
		} else {
			xlog.Warn("request failed", "status", status, "err", err)
		}
	}

	resp := NewApiResponse(data, err)
	d, e := json.Marshal(resp)
	if e != nil {
		xlog.Error("failed to marshal response", "err", e)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(e.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(d)
}

func WriteJSONResponseError(w http.ResponseWriter, status int, err error) {
	WriteJSONResponse[string](w, status, err.Error(), err)
}
