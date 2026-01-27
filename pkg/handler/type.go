package handler

import (
	"encoding/json"
	"net/http"
)

type ApiResponse[T any] struct {
	Error error `json:"error"`
	Data  T     `json:"data"`
}

func NewApiResponse[T any](data T, err error) *ApiResponse[T] {
	return &ApiResponse[T]{
		Data:  data,
		Error: err,
	}
}

func WriteJSONResponse[T any](w http.ResponseWriter, status int, data T, err error) {
	resp := NewApiResponse(data, err)
	d, e := json.Marshal(resp)
	if e != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(e.Error()))
		return
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(d)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(d)
}

func WriteJSONResponseError(w http.ResponseWriter, status int, err error) {
	WriteJSONResponse(w, status, err.Error(), err)
}
