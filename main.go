package main

import (
	"net/http"
)

func main() {
	mustBindEnv()
	startTokenGC(defaultTokenCleanerInterval)

	router := NewRouter()

	err := http.ListenAndServe(":"+env.ServerPort, router)
	if err != nil {
		panic(err.Error())
	}
}
