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

var jwtSecret = []byte(env.GetEnv("APP_SECRET", ""))

func GenerateToken(ctx context.Context, username, fullName, tokenType string) (string, error) {
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
	result, err := token.SignedString(jwtSecret)
	if err != nil {
		return result, fmt.Errorf("error generating token", err)
	}
	return result, nil
}

func ValidateToken(ctx context.Context, token string) (*ClaimToken, error) {
	var (
		claimToken *ClaimToken
		ok         bool
	)

	jwtToken, err := jwt.ParseWithClaims(token, &ClaimToken{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("failed to validate method jwt: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("error parsing token", err)
	}

	if claimToken, ok = jwtToken.Claims.(*ClaimToken); !ok || !jwtToken.Valid {
		return nil, fmt.Errorf("error validating token", err)
	}

	return claimToken, nil
}
