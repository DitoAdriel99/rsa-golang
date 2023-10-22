package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// RSAPublicKeyFromPEMBase64 importing from PEM Base64 encoded into object *rsa.PublicKey
func RSAPublicKeyFromPEMBase64(encoded string) (*rsa.PublicKey, error) {
	decodeString, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return RSAPublicKeyFromPEM(decodeString)
}

// RSAPublicKeyFromPEM importing from PEM format into object *rsa.PublicKey
func RSAPublicKeyFromPEM(pemKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

// RSAPrivateKeyFromPEMBase64 importing from PEM Base64 encoded into object *rsa.PrivateKey
func RSAPrivateKeyFromPEMBase64(encoded string) (*rsa.PrivateKey, error) {
	decodeString, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return RSAPrivateKeyFromPEM(decodeString)
}

// RSAPrivateKeyFromPEM importing from PEM format into object *rsa.PrivateKey
func RSAPrivateKeyFromPEM(pemKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
