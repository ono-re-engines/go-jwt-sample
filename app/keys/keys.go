package keys

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"

	"github.com/pkg/errors"
)

//go:embed private.key
var privateKey []byte

//go:embed public.key
var publicKey []byte

func ParsePrivateKey() (any, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("failed to parse private key")
	}

	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid private key type")
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse private key")
	}

	return parsedKey, nil
}

func ParsePublicKey() (any, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("failed to parse public key")
	}

	if block.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("invalid block type")
	}

	parsedKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parsedKey for publicKey")
	}

	return parsedKey, nil
}
