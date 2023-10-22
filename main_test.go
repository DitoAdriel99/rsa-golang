package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"os"
	"testing"

	"github.com/joho/godotenv"
)

var (
	TEMP []byte
)

func TestEncrypt(t *testing.T) {

	// Load environment variables from .env
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	pubKey := os.Getenv("PUBLIC_KEY_BASE64")
	// privKey := os.Getenv("PRIVATE_KEY_BASE64")
	dummyByte := []byte("Dummy Data")
	t.Log("Data :", string(dummyByte))

	publicKey, _ := RSAPublicKeyFromPEMBase64(pubKey)

	encryptedData, _ := rsa.EncryptPKCS1v15(rand.Reader, publicKey, dummyByte)

	t.Log("Encrypted :", encryptedData)

	TEMP = encryptedData

}

func TestDecrypt(t *testing.T) {

	privKey := os.Getenv("PRIVATE_KEY_BASE64")

	privateKey, _ := RSAPrivateKeyFromPEMBase64(privKey)

	decryptedData, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, TEMP)

	t.Log("Decrypted:", string(decryptedData))
}
