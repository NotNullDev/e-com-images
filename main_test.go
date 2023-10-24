package main

import (
	"fmt"
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

	_, ok := isTokenValid(token, secret)

	if !ok {
		t.Fatalf("token didn't passed validation")
		return
	}
}

func Test_expiredTokenIsNotValid(t *testing.T) {
	token := createTokenWithExpire(secret, time.Millisecond*1)
	println(token)

	time.Sleep(time.Millisecond * 5)

	_, ok := isTokenValid(token, secret)

	if ok {
		t.Fatalf("token is valid but should be expired")
		return
	}
}

func Test_nonExpiredTokenIsValid(t *testing.T) {
	token := createTokenWithExpire(secret, time.Second*10)
	println(token)

	_, ok := isTokenValid(token, secret)

	if !ok {
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
	os.Setenv("ADMIN_KEY", secret)

	mustBindEnv()

	router := NewRouter()
	server := httptest.NewServer(router)
	defer server.Close()

	client := http.Client{}

	presignUrl, _ := url.Parse(server.URL + "/images/presign")

	req := http.Request{
		URL: presignUrl,
		Header: map[string][]string{
			"Authorization": {"Bearer " + secret},
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
	os.Setenv("ADMIN_KEY", secret)
	mustBindEnv()

	router := NewRouter()
	server := httptest.NewServer(router)
	defer server.Close()

	client := http.Client{}

	presignUrl, _ := url.Parse(server.URL + "/images/presign")

	tokenBytes := []byte(secret)

	lastLetter := tokenBytes[len(secret)-1]
	if lastLetter == 'a' {
		tokenBytes[len(secret)-1] = 'b'
	} else {
		tokenBytes[len(secret)-1] = 'a'
	}
	modifiedSecret := string(tokenBytes)

	req := http.Request{
		URL: presignUrl,
		Header: map[string][]string{
			"Authorization": {"Bearer " + modifiedSecret},
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

var tmpFilePattern = "write-to-disk-test-file-*"

func BenchmarkWriteToDiskAlloc(b *testing.B) {
	var fNames []string

	os.Mkdir("files", 0777)

	for i := 0; i < b.N; i++ {
		temp, err := os.CreateTemp(os.TempDir(), tmpFilePattern)
		if err != nil {
			panic(err.Error())
		}
		write, err := temp.Write([]byte("hello world!"))
		if err != nil || write == 0 {
			panic("Failed to create dummy file!")
		}
		fNames = append(fNames, temp.Name())
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		createdFileName, err := writeFileToDisk(fNames[i], "files")
		if err != nil {
			b.Fatalf("Failed to create file with name [%s]", fNames[i])
			return
		}
		_ = createdFileName
	}

	b.StopTimer()
	for _, fName := range fNames {
		err := os.Remove(fName)
		if err != nil {
			println(err.Error())
		}
	}
	fmt.Printf("Removed %d files", len(fNames))
}
