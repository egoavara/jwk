package jwk_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestDecodeEC(t *testing.T) {
	prik, err := rsa.GenerateMultiPrimeKey(rand.Reader, 5, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkc8, err := x509.MarshalPKCS8PrivateKey(prik)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(pem.EncodeToMemory(&pem.Block{
		Type:    "PRIVATE KEY",
		Headers: map[string]string{},
		Bytes:   pkc8,
	})))
}
