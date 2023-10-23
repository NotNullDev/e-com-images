package main

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Environment struct {
	JwtSecret            string `json:"jwtSecret"`
	ServerPort           string `json:"serverPort"`
	PresignLifeMs        int    `json:"presignLifeMs"`
	FileStorageDirectory string `json:"fileStorageDirectory"`
}

type ErrorMessage struct {
	Error     string `json:"error"`
	ErrorCode string `json:"errorCode"`
}

type PresignedTokens struct {
	presignedTokens []jwt.Token
	tokensLock      sync.Mutex
}

var presignedTokens = PresignedTokens{
	presignedTokens: make([]jwt.Token, 0),
	tokensLock:      sync.Mutex{},
}

type PresignTokenResponse struct {
	Token string `json:"token"`
}

var env Environment
var createdToken string

const (
	defaultServerPort           = "8080"
	defaultPresignLifeMs        = 1000 * 60 * 5
	defaultTokenCleanerInterval = 5 * time.Minute
	defaultFileStorageDirectory = "files"
)

const (
	presignTokenQueryParamName = "presignToken"
	multipartFormMaxMemory     = 0
)

var (
	written0BytesError = fmt.Errorf("written 0 bytes")
)

func main() {
	mustBindEnv()
	createAndPrintJwt()
	startTokenCleaner(defaultTokenCleanerInterval)

	router := NewRouter()

	err := http.ListenAndServe(":"+env.ServerPort, router)
	if err != nil {
		panic(err.Error())
	}
}

func NewRouter() *chi.Mux {
	router := chi.NewRouter()
	initRoutes(router)

	return router
}

func initRoutes(r *chi.Mux) {
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})

	r.Route("/images", func(r chi.Router) {
		r.Use(validToken)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("you are in!"))
		})

		r.Get("/presign", func(writer http.ResponseWriter, request *http.Request) {
			token := createTokenWithExpire(env.JwtSecret, defaultPresignLifeMs)
			writeResponse(writer, PresignTokenResponse{
				Token: token,
			}, 200)
		})
	})

	r.Route("/upload", func(r chi.Router) {
		r.Post("/", func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get(presignTokenQueryParamName)
			if token == "" {
				writeError(w, fmt.Sprintf("[%s] queryParam is missing", presignTokenQueryParamName), "QUERY_PARAM_MISSING", 400)
				return
			}

			if !isTokenValid(env.JwtSecret, token) {
				writeError(w, "Invalid presigned token", "INVALID_PRESIGNED_TOKEN", 403)
				return
			}

			err := r.ParseMultipartForm(multipartFormMaxMemory)
			if err != nil {
				writeError(w, "Could not parse multipart form", "INVALID_MULTIPART_FORM", 500)
				return
			}

			fileHeaders := r.MultipartForm.File["file"]

			if len(fileHeaders) != 1 {
				writeError(w, "You must provide exactly one file", "INVALID_AMOUNT_OF_FILES", 400)
				return
			}

			createdFName, err := writeFileToDisk(fileHeaders[0], env.FileStorageDirectory)
			if err != nil {
				writeError(w, "Failed to write file to a disk", "WRITE_FILE_TO_DISK_FAILED", 500)
				return
			}

			println(createdFName)
			panic("implementation WIP")

			//w.WriteHeader(200)
		})
	})
}

func writeFileToDisk(fHeader *multipart.FileHeader, filesDirectory string) (string, error) {
	fHandle, err := fHeader.Open()
	if err != nil {
		return "", err
	}
	defer fHandle.Close()

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

func startTokenCleaner(cleanEveryMs time.Duration) {
	go func() {
		logInfo("Token cleaner started job")
		var indexesToDelete []int

		presignedTokens.tokensLock.Lock()

		for idx, token := range presignedTokens.presignedTokens {
			if token.Claims == nil {
				logError("claims are missing from in the token")
				indexesToDelete = append(indexesToDelete, idx)
				continue
			}

			exp, err := token.Claims.GetExpirationTime()
			if err != nil {
				logError("expiration date is missing in the token")
				indexesToDelete = append(indexesToDelete, idx)
				continue
			}

			if exp.After(time.Now()) {
				indexesToDelete = append(indexesToDelete, idx)
			}
		}

		for _, toDeleteIdx := range indexesToDelete {
			presignedTokens.presignedTokens = append(presignedTokens.presignedTokens[:toDeleteIdx], presignedTokens.presignedTokens[toDeleteIdx:]...)
		}

		presignedTokens.tokensLock.Unlock()
		logInfo(fmt.Sprintf("Token cleaner completed job. Removed %d from %d keys", len(indexesToDelete), len(presignedTokens.presignedTokens)))
		time.Sleep(cleanEveryMs)
	}()
}

func createAndPrintJwt() {
	createdToken = createToken(env.JwtSecret)
	logInfo(fmt.Sprintf("API KEY: [%s]", createdToken))
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
		serverPort = defaultServerPort
	}
	env.ServerPort = serverPort

	presignLifeMsString := os.Getenv("PRESIGN_LIFE_MS")
	env.PresignLifeMs = defaultPresignLifeMs

	if presignLifeMsString != "" {
		resignedLife, err := strconv.Atoi(presignLifeMsString)
		if err != nil {
			logError(fmt.Sprintf("Invalid PRESIGN_LIFE_MS, falling back to default: [%d]ms", env.PresignLifeMs))
		}
		env.PresignLifeMs = resignedLife
	}

	fileStorageDir := os.Getenv("FILE_STORAGE_DIRECTORY")
	if fileStorageDir == "" {
		logInfo(fmt.Sprintf("FILE_STORAGE_DIRECTORY not specified, using default: [%s]", defaultFileStorageDirectory))
		err := os.Mkdir(defaultFileStorageDirectory, 0777)
		if err != nil {
			panic(fmt.Sprintf("Could not create default file storage directory!: %s", err.Error()))
		}
		env.FileStorageDirectory = defaultFileStorageDirectory
	} else {
		env.FileStorageDirectory = fileStorageDir
	}

}

func validToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("Authorization")
		apiKeyParts := strings.Split(apiKey, "Bearer ")

		if len(apiKeyParts) != 2 {
			writeError(w, "authorization header is not in a valid format", "INVALID_BEARER_HEADER_FORMAT", 400)
			return
		}

		key := apiKeyParts[1]

		if isTokenValid(key, env.JwtSecret) {
			next.ServeHTTP(w, r)
			return
		}

		writeError(w, "Invalid api key", "INVALID_API_KEY", 403)
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

func (tokens *PresignedTokens) IsBlackmailed(token jwt.Token) bool {
	tokens.tokensLock.Lock()
	for _, t := range tokens.presignedTokens {
		if string(t.Signature) == string(token.Signature) {
			return true
		}
	}
	tokens.tokensLock.Unlock()
	return false
}

func (tokens *PresignedTokens) AddToBlackmail(token jwt.Token) {
	tokens.tokensLock.Lock()
	tokens.presignedTokens = append(tokens.presignedTokens, token)
}
