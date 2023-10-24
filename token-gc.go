package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"sync"
	"time"
)

var presignedTokens = PresignedTokens{
	presignedTokens: make([]jwt.Token, 0),
	tokensLock:      sync.Mutex{},
}

func (tokens *PresignedTokens) IsValid(token *jwt.Token) bool {
	tokens.tokensLock.Lock()
	defer tokens.tokensLock.Unlock()

	found := false
	for _, t := range tokens.presignedTokens {
		if string(t.Signature) == string(token.Signature) {
			found = true
			break
		}
	}

	return found
}

func (tokens *PresignedTokens) Add(token *jwt.Token) {
	tokens.tokensLock.Lock()
	defer tokens.tokensLock.Unlock()

	tokens.presignedTokens = append(tokens.presignedTokens, *token)
}

func (tokens *PresignedTokens) Remove(token *jwt.Token) {
	tokens.tokensLock.Lock()
	defer tokens.tokensLock.Unlock()

	foundIdx := -1
	for i := range tokens.presignedTokens {
		if tokens.presignedTokens[i].Raw == token.Raw {
			foundIdx = i
			break
		}
	}
	if foundIdx != -1 {
		tokens.presignedTokens = append(tokens.presignedTokens[:foundIdx], tokens.presignedTokens[foundIdx+1:]...)
	} else {
		logError(fmt.Sprintf("Tried to remove token, which doesn't belong to the list of tokens: [%s]", token.Raw))
	}
}

func startTokenGC(cleanEveryMs time.Duration) {
	go func() {
		for {
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

			logInfo(fmt.Sprintf("Token cleaner completed job. Removed %d from %d keys", len(indexesToDelete), len(presignedTokens.presignedTokens)))
			presignedTokens.tokensLock.Unlock()
			time.Sleep(cleanEveryMs)
		}
	}()
}
