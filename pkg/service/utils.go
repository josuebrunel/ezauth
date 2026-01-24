package service

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/gofrs/uuid/v5"
)

// GenerateID generates a random UUID-like string using gorfs
func GenerateID() string {
	return uuid.Must(uuid.NewV4()).String()
}

// GenerateToken generates a secure random token
func GenerateToken() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}
