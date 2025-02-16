package jwt

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kooroshh/fiber-boostrap/pkg/env"
	"time"
)

type ClaimToken struct {
	Username string `json:"username"`
	FullName string `json:"full_name"`
	jwt.RegisteredClaims
}

var MapTypeToken = map[string]time.Duration{
	"token":         time.Hour * 24,
	"refresh_token": time.Hour * 72,
}

func GenerateToken(ctx context.Context, username, fullName, tokenType string) (string, error) {
	secret := env.GetEnv("APP_SECRET", "")
	claimToken := ClaimToken{
		Username: username,
		FullName: fullName,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    env.GetEnv("APP_NAME", ""),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(MapTypeToken[tokenType])),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claimToken)
	result, err := token.SignedString([]byte(secret))
	if err != nil {
		return result, fmt.Errorf("error generating token", err)
	}
	return result, nil
}
