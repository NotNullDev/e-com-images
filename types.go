package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"sync"
)

var (
	written0BytesError = fmt.Errorf("written 0 bytes")
)

type ErrorMessage struct {
	Error     string `json:"error"`
	ErrorCode string `json:"errorCode"`
}

// PresignedTokens list of the tokens that are valid for the application
// this list is required to avoid jwt leaking
type PresignedTokens struct {
	presignedTokens []jwt.Token
	tokensLock      sync.Mutex
}

type PresignTokenResponse struct {
	Token string `json:"token"`
}

type UploadFileResponse struct {
	FileName string `json:"fileName"`
}
