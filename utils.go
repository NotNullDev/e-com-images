package main

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

func writeFileToDiskFHeader(fHeader *multipart.FileHeader, filesDirectory string) (string, error) {
	fHandle, err := fHeader.Open()
	defer fHandle.Close()
	if err != nil {
		return "", err
	}

	diskFile, err := os.CreateTemp(filesDirectory, "")
	if err != nil {
		return "", err
	}

	written, err := io.Copy(diskFile, fHandle)
	if err != nil {
		return "", err
	}

	if written == 0 {
		return "", written0BytesError
	}

	// 1: to remove forward slash
	return strings.TrimPrefix(diskFile.Name(), filesDirectory)[1:], nil
}

func writeFileToDisk(fName string, filesDirectory string) (string, error) {
	fHandle, err := os.Open(fName)
	if err != nil {
		return "", err
	}

	diskFile, err := os.CreateTemp(filesDirectory, "")
	if err != nil {
		return "", err
	}

	written, err := io.Copy(diskFile, fHandle)
	if err != nil {
		return "", err
	}

	if written == 0 {
		return "", written0BytesError
	}

	return diskFile.Name(), nil
}

func validAdminTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("Authorization")
		apiKeyParts := strings.Split(apiKey, "Bearer ")

		if len(apiKeyParts) != 2 {
			writeError(w, "authorization header is not in a valid format", "INVALID_BEARER_HEADER_FORMAT", 400)
			return
		}

		key := apiKeyParts[1]

		ok := key == env.AdminKey
		if !ok {
			writeError(w, "Invalid api key", "API_KEY_INVALID", 403)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, errorMessage string, errorCode string, httpCode int) {
	errContent := ErrorMessage{
		Error:     errorMessage,
		ErrorCode: errorCode,
	}

	respBody, err := json.Marshal(errContent)
	if err != nil {
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	w.Write(respBody)
}

func writeResponse(w http.ResponseWriter, body interface{}, code int) {
	respBody, err := json.Marshal(body)
	if err != nil {
		logError(err.Error())
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(respBody)
}

func createToken(secret string) string {
	return createTokenWithExpire(secret, 24*time.Hour*365)
}

func createTokenWithExpire(secret string, lifeDurationFromNow time.Duration) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(lifeDurationFromNow).Unix(),
	})

	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		logError("Should not happen: failed to create jwt")
		panic(err.Error())
	}

	return signed
}

func isTokenValid(token string, secret string) (*jwt.Token, bool) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})
	if err != nil {
		logError(err.Error())
		return nil, false
	}

	if parsedToken.Valid {
		return parsedToken, true
	}

	return nil, false
}

func logError(err string) {
	log.Printf(fmt.Sprintf("[ERROR] %s", err))
}

func logInfo(msg string) {
	log.Printf("[INFO] %s", msg)
}
