package main

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Environment struct {
	JwtSecret  string `json:"jwtSecret"`
	ServerPort string `json:"serverPort"`
}

type ErrorMessage struct {
	Error string `json:"error"`
}

var env Environment

func main() {
	router := chi.NewRouter()

	mustBindEnv()
	createAndPrintJwt()

	initRoutes(router)

	err := http.ListenAndServe(":"+env.ServerPort, router)
	if err != nil {
		panic(err.Error())
	}
}

func initRoutes(r *chi.Mux) {
	r.Route("/images", func(r chi.Router) {
		r.Use(validToken)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("you are in!"))
		})
	})
}

func createAndPrintJwt() {
	token := createToken(env.JwtSecret)
	logInfo(fmt.Sprintf("API KEY: [%s]", token))
}

func mustBindEnv() {
	jwtSecret := os.Getenv("JWT_SECRET")
	if len(jwtSecret) < 16 {
		msg := "JWT_SECRET is missing or invalid"
		panic(msg)
	}
	env.JwtSecret = jwtSecret

	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = "8080"
	}
	env.ServerPort = serverPort

}

func validToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("Authorization")
		apiKeyParts := strings.Split(apiKey, "Bearer ")

		if len(apiKeyParts) != 2 {
			writerError(w, "authorization header is not in a valid format", 400)
			return
		}

		key := apiKeyParts[1]

		if isTokenValid(key, env.JwtSecret) {
			next.ServeHTTP(w, r)
			return
		}

		writerError(w, "Invalid api key", 403)
	})
}

func writerError(w http.ResponseWriter, errorMessage string, errorCode int) {
	errContent := ErrorMessage{
		Error: errorMessage,
	}

	respBody, err := json.Marshal(errContent)
	if err != nil {
		return
	}

	w.WriteHeader(errorCode)
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

func isTokenValid(token string, secret string) bool {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(secret), nil
	})
	if err != nil {
		logError(err.Error())
		return false
	}

	if parsedToken.Valid {
		return true
	}

	return false
}

func logError(err string) {
	log.Printf(fmt.Sprintf("[ERROR] %s", err))
}

func logInfo(msg string) {
	log.Printf("[INFO] %s", msg)
}
