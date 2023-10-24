package main

import (
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"path"
)

func NewRouter() *chi.Mux {
	router := chi.NewRouter()
	initRoutes(router)

	return router
}

func initRoutes(r *chi.Mux) {
	r.Handle("/public/*", http.StripPrefix("/public/", http.FileServer(http.Dir(env.FileStorageDirectory))))

	r.Get("/health", GetHealth())

	r.Route("/upload", func(r chi.Router) {
		r.Post("/", PostUpload())
	})

	r.Route("/images", func(r chi.Router) {
		r.Use(validAdminTokenMiddleware)

		r.Get("/presign", GetImagesPresign())

		r.Get("/", GetImages())

		r.Delete("/{id}", DeleteById)
	})
}

func DeleteById(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	err := os.Remove(path.Join(env.FileStorageDirectory, id))
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, "File not found", "FILE_NOT_FOUND", 400)
		} else {
			logError(err.Error())
			writeError(w, "Something went wrong", "INTERNAL_SERVER_ERROR", 500)
		}
		return
	}

	w.WriteHeader(204)
}

func PostUpload() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get(presignTokenQueryParamName)
		if token == "" {
			writeError(w, fmt.Sprintf("[%s] queryParam is missing", presignTokenQueryParamName), "QUERY_PARAM_MISSING", 400)
			return
		}

		validatedToken, ok := isTokenValid(token, env.JwtSecret)

		if !ok {
			writeError(w, "Invalid presigned token", "INVALID_PRESIGNED_TOKEN", 403)
			return
		}

		isInTheList := presignedTokens.IsValid(validatedToken)
		if !isInTheList {
			writeError(w, "Token has been used before", "TOKEN_ALREADY_USED", 403)
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

		createdFName, err := writeFileToDiskFHeader(fileHeaders[0], env.FileStorageDirectory)
		if err != nil {
			writeError(w, "Failed to write file to a disk", "WRITE_FILE_TO_DISK_FAILED", 500)
			return
		}
		writeResponse(w, UploadFileResponse{FileName: createdFName}, 200)

		presignedTokens.Remove(validatedToken)
	}
}

func GetImagesPresign() func(writer http.ResponseWriter, request *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		token := createTokenWithExpire(env.JwtSecret, env.PresignLifeMs)
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return []byte(env.JwtSecret), nil
		})
		if err != nil {
			writeError(writer, "Failed to parse JWT.", "JWT_PARSING_FAILED", 400)
			return
		}

		presignedTokens.Add(parsedToken)

		writeResponse(writer, PresignTokenResponse{
			Token: token,
		}, 200)
	}
}

func GetImages() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("you are in!"))
	}
}

func GetHealth() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}
}
