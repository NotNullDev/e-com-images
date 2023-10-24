package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Environment struct {
	JwtSecret            string        `json:"jwtSecret"`
	ServerPort           string        `json:"serverPort"`
	PresignLifeMs        time.Duration `json:"presignLifeMs"`
	FileStorageDirectory string        `json:"fileStorageDirectory"`
	AdminKey             string        `json:"adminKey"`
}

var env Environment

const (
	defaultServerPort           = "8080"
	defaultPresignLifeMs        = 1000 * 60 * 5 // 5 minutes
	defaultTokenCleanerInterval = 5 * time.Minute
	defaultFileStorageDirectory = "files"
)

const (
	presignTokenQueryParamName = "presignToken"
	multipartFormMaxMemory     = 0
)

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
	env.PresignLifeMs = defaultPresignLifeMs * time.Millisecond

	if presignLifeMsString != "" {
		resignedLife, err := strconv.Atoi(presignLifeMsString)
		if err != nil {
			logError(fmt.Sprintf("Invalid PRESIGN_LIFE_MS, falling back to default: [%d]ms", env.PresignLifeMs))
		}
		env.PresignLifeMs = time.Duration(resignedLife) * time.Millisecond
	}

	fileStorageDir := os.Getenv("FILE_STORAGE_DIRECTORY")
	if fileStorageDir == "" {
		logInfo(fmt.Sprintf("FILE_STORAGE_DIRECTORY not specified, using default: [%s]", defaultFileStorageDirectory))
		if _, err := os.Stat(defaultFileStorageDirectory); os.IsNotExist(err) {
			err := os.Mkdir(defaultFileStorageDirectory, 0777)
			if err != nil {
				panic(fmt.Sprintf("Could not create default file storage directory!: %s", err.Error()))
			}
		}
		env.FileStorageDirectory = defaultFileStorageDirectory
	} else {
		env.FileStorageDirectory = fileStorageDir
	}

	adminKey := strings.TrimSpace(os.Getenv("ADMIN_KEY"))
	if len(adminKey) < 16 {
		panic("Invalid ADMIN_KEY: admin key must have at least 16 characters")
	}
	env.AdminKey = adminKey

}
