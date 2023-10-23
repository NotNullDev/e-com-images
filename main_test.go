package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

// openssl rand -hex 32
const (
	secret = "6a8fc485905a9895c76bc8429aa3f187ebd1048f7c43cfdd978439b4ce681fa3"
)

func Test_createToken(t *testing.T) {
	token := createToken(secret)
	println(token)

	isValid := isTokenValid(token, secret)

	if !isValid {
		t.Fatalf("token didn't passed validation")
		return
	}
}

func Test_expiredTokenIsNotValid(t *testing.T) {
	token := createTokenWithExpire(secret, time.Millisecond*1)
	println(token)

	time.Sleep(time.Millisecond * 5)

	isValid := isTokenValid(token, secret)

	if isValid {
		t.Fatalf("token is valid but should be expired")
		return
	}
}

func Test_nonExpiredTokenIsValid(t *testing.T) {
	token := createTokenWithExpire(secret, time.Second*10)
	println(token)

	isValid := isTokenValid(token, secret)

	if !isValid {
		t.Fatalf("token should be valid but is not")
		return
	}
}

func Test_healthEndpointIsWorking(t *testing.T) {
	router := NewRouter()
	server := httptest.NewServer(router)
	defer server.Close()

	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	if resp.StatusCode != 200 {
		t.Fatalf("Invalid response code: expected [200], received [%d]", resp.StatusCode)
		return
	}
}

func Test_PresignWorksWithDefaultJWT(t *testing.T) {
	os.Setenv("JWT_SECRET", secret)
	mustBindEnv()
	createAndPrintJwt()

	router := NewRouter()
	server := httptest.NewServer(router)
	defer server.Close()

	client := http.Client{}

	presignUrl, _ := url.Parse(server.URL + "/images/presign")

	req := http.Request{
		URL: presignUrl,
		Header: map[string][]string{
			"Authorization": {"Bearer " + createdToken},
		},
		Method: "GET",
	}

	resp, err := client.Do(&req)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	if resp.StatusCode != 200 {
		t.Fatalf("Invalid response code: expected [200], received [%d]", resp.StatusCode)
		return
	}
}

func Test_PresignDoesntWorksWithModifiedDefaultJWT(t *testing.T) {
	os.Setenv("JWT_SECRET", secret)
	mustBindEnv()
	createAndPrintJwt()

	router := NewRouter()
	server := httptest.NewServer(router)
	defer server.Close()

	client := http.Client{}

	presignUrl, _ := url.Parse(server.URL + "/images/presign")

	tokenBytes := []byte(createdToken)

	lastLetter := tokenBytes[len(createdToken)-1]
	if lastLetter == 'a' {
		tokenBytes[len(createdToken)-1] = 'b'
	} else {
		tokenBytes[len(createdToken)-1] = 'a'
	}
	createdToken = string(tokenBytes)

	req := http.Request{
		URL: presignUrl,
		Header: map[string][]string{
			"Authorization": {"Bearer " + createdToken},
		},
		Method: "GET",
	}

	resp, err := client.Do(&req)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}

	if resp.StatusCode != 403 {
		t.Fatalf("Invalid response code: expected [403], received [%d]", resp.StatusCode)
		return
	}
}
