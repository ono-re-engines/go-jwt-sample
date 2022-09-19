package jwttkn

import (
	"github.com/golang-jwt/jwt/v4"
	"github.com/ono-re-engines/go-jwt-sample/app/keys"
	"github.com/pkg/errors"
)

func NewRSASignedStringWithClaims(claims *Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	key, err := keys.ParsePrivateKey()
	if err != nil {
		return "", errors.Wrap(err, "failed to parse private key")
	}

	ss, err := t.SignedString(key)
	if err != nil {
		return "", errors.Wrap(err, "signing with PrivateKey failed")
	}

	return ss, nil
}

func ParseRSASigned(tokenString string) (*jwt.Token, error) {
	key, err := keys.ParsePublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "parsing public key failed")
	}

	return parse(tokenString, key)
}

func GetClaims(token *jwt.Token) (jwt.MapClaims, error) {
	if c, ok := token.Claims.(jwt.MapClaims); ok {
		return c, nil
	} else {
		return nil, errors.New("invalid token")
	}
}

func parse(tokenString string, key any) (*jwt.Token, error) {
	parsedToken, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("invalid signing method")
		}

		return key, nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "parsing token failed")
	}
	if !parsedToken.Valid {
		return nil, errors.New("invalid token")
	}

	return parsedToken, nil
}
