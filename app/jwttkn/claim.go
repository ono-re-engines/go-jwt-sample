package jwttkn

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func NewClaims(code string) *Claims {
	now := time.Now()
	return &Claims{
		code,
		jwt.RegisteredClaims{
			Issuer:    "test",
			ExpiresAt: jwt.NewNumericDate(now.Add(4 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
}

type Claims struct {
	Code string `json:"code"`
	jwt.RegisteredClaims
}
