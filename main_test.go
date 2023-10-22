package main

import (
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
