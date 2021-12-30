package jwk_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/egoavara/jwk"
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

func TestDecodeSet(t *testing.T) {
	// set inner key with unknown field
	tc0 := `{
		"keys": [
			{
				"kty": "RSA",
				"use": "sig",
				"n": "tCwhHOxX_ylh5kVwfVqW7QIBTIsPjkjCjVCppDrynuF_3msEdtEaG64eJUz84ODFNMCC0BQ57G7wrKQVWkdSDxWUEqGk2BixBiHJRWZdofz1WOBTdPVicvHW5Zl_aIt7uXWMdOp_SODw-O2y2f05EqbFWFnR2-1y9K8KbiOp82CD72ny1Jbb_3PxTs2Z0F4ECAtTzpDteaJtjeeueRjr7040JAjQ-5fpL5D1g8x14LJyVIo-FL_y94NPFbMp7UCi69CIfVHXFO8WYFz949og-47mWRrID5lS4zpx-QLuvNhUb_lSqmylUdQB3HpRdOcYdj3xwy4MHJuu7tTaf0AmCQ",
				"alg": "RS256",
				"e": "AQAB",
				"kid": "d98f49bc6ca4581eae8dfadd494fce10ea23aab0",
				"unknown": "field"
			}
		]
	}`
	// WithStrict test
	{
		n := "tCwhHOxX_ylh5kVwfVqW7QIBTIsPjkjCjVCppDrynuF_3msEdtEaG64eJUz84ODFNMCC0BQ57G7wrKQVWkdSDxWUEqGk2BixBiHJRWZdofz1WOBTdPVicvHW5Zl_aIt7uXWMdOp_SODw-O2y2f05EqbFWFnR2-1y9K8KbiOp82CD72ny1Jbb_3PxTs2Z0F4ECAtTzpDteaJtjeeueRjr7040JAjQ-5fpL5D1g8x14LJyVIo-FL_y94NPFbMp7UCi69CIfVHXFO8WYFz949og-47mWRrID5lS4zpx-QLuvNhUb_lSqmylUdQB3HpRdOcYdj3xwy4MHJuu7tTaf0AmCQ"
		e := "AQAB"
		rawn, err := base64.RawURLEncoding.DecodeString(n)
		if err != nil {
			panic(err)
		}
		rawe, err := base64.RawURLEncoding.DecodeString(e)
		if err != nil {
			panic(err)
		}
		tc0set0key := &jwk.Key{
			KeyType:   "RSA",
			KeyUse:    "sig",
			Algorithm: "RS256",
			KeyID:     "d98f49bc6ca4581eae8dfadd494fce10ea23aab0",
			Raw: &rsa.PublicKey{
				N: new(big.Int).SetBytes(rawe).SetBytes(rawn),
				E: int(new(big.Int).SetBytes(rawe).Int64()),
			},
		}
		son, err := jwk.DecodeSet(strings.NewReader(tc0), jwk.WithStrict(true))
		if err == nil {
			t.Error("error expected because there is `keys.0.unknown` field")
		}
		if son != nil {
			t.Errorf("expected <nil> but got %v", son)
		}
		soff, err := jwk.DecodeSet(strings.NewReader(tc0), jwk.WithStrict(false))
		if err != nil {
			t.Errorf("err must be nil bot got %v", err)
		}
		if !reflect.DeepEqual(soff.Keys[0], tc0set0key) {
			t.Errorf("deep eq failed, %v != %v", soff.Keys[0], tc0set0key)
		}

	}
}
