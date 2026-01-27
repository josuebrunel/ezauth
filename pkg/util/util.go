package util

import (
	"crypto/rand"
	"encoding/hex"
)

func Must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func Deref[T any](t *T) T {
	if t == nil {
		var zero T
		return zero
	}
	return *t
}

func RandomString(n int) string {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
