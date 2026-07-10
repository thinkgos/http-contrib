package authorize

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

func parseRSAPrivateKey(privateKey string) (*rsa.PrivateKey, error) {
	priv, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		priv, err = os.ReadFile(privateKey)
		if err != nil {
			priv = []byte(privateKey)
		}
	}
	return jwt.ParseRSAPrivateKeyFromPEM(priv)
}

func parseRSAPublicKey(publicKey string) (*rsa.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		pub, err = os.ReadFile(publicKey)
		if err != nil {
			pub = []byte(publicKey)
		}
	}
	return jwt.ParseRSAPublicKeyFromPEM(pub)
}

func parseECPrivateKey(privateKey string) (*ecdsa.PrivateKey, error) {
	priv, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		priv, err = os.ReadFile(privateKey)
		if err != nil {
			priv = []byte(privateKey)
		}
	}
	return jwt.ParseECPrivateKeyFromPEM(priv)
}

func parseECPublicKey(publicKey string) (*ecdsa.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		pub, err = os.ReadFile(publicKey)
		if err != nil {
			pub = []byte(publicKey)
		}
	}
	return jwt.ParseECPublicKeyFromPEM(pub)
}

func parseEdPrivateKey(privateKey string) (crypto.PrivateKey, error) {
	priv, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		priv, err = os.ReadFile(privateKey)
		if err != nil {
			priv = []byte(privateKey)
		}
	}
	return jwt.ParseEdPrivateKeyFromPEM(priv)
}

func parseEdPublicKey(publicKey string) (crypto.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		pub, err = os.ReadFile(publicKey)
		if err != nil {
			pub = []byte(publicKey)
		}
	}
	return jwt.ParseEdPublicKeyFromPEM(pub)
}
