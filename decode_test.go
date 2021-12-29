package jwk_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
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

func TestDecodeRSA(t *testing.T) {
	rawJWKSet := `{
		"keys": [
			{
				"use": "sig",
				"n": "tCwhHOxX_ylh5kVwfVqW7QIBTIsPjkjCjVCppDrynuF_3msEdtEaG64eJUz84ODFNMCC0BQ57G7wrKQVWkdSDxWUEqGk2BixBiHJRWZdofz1WOBTdPVicvHW5Zl_aIt7uXWMdOp_SODw-O2y2f05EqbFWFnR2-1y9K8KbiOp82CD72ny1Jbb_3PxTs2Z0F4ECAtTzpDteaJtjeeueRjr7040JAjQ-5fpL5D1g8x14LJyVIo-FL_y94NPFbMp7UCi69CIfVHXFO8WYFz949og-47mWRrID5lS4zpx-QLuvNhUb_lSqmylUdQB3HpRdOcYdj3xwy4MHJuu7tTaf0AmCQ",
				"alg": "RS256",
				"e": "AQAB",
				"kid": "d98f49bc6ca4581eae8dfadd494fce10ea23aab0",
				"alg": ["verify", "sign", "enc"],
				"kty": "RSA",
				"oth" : [
					{
						"r" : "",
						"d" : "",
						"t" : ""
					}
				]
			},
			{
				"e": "AQAB",
				"alg": "RS256",
				"use": "sig",
				"kty": "RSA",
				"kid": "03e84aed4ef4431014e8617567864c4efaaaede9",
				"n": "ma2uRyBeSEOatGuDpCiV9oIxlDWix_KypDYuhQfEzqi_BiF4fV266OWfyjcABbam59aJMNvOnKW3u_eZM-PhMCBij5MZ-vcBJ4GfxDJeKSn-GP_dJ09rpDcILh8HaWAnPmMoi4DC0nrfE241wPISvZaaZnGHkOrfN_EnA5DligLgVUbrA5rJhQ1aSEQO_gf1raEOW3DZ_ACU3qhtgO0ZBG3a5h7BPiRs2sXqb2UCmBBgwyvYLDebnpE7AotF6_xBIlR-Cykdap3GHVMXhrIpvU195HF30ZoBU4dMd-AeG6HgRt4Cqy1moGoDgMQfbmQ48Hlunv9_Vi2e2CLvYECcBw"
			}
		]
	}`
	var jwkset map[string]interface{}
	if err := json.Unmarshal([]byte(rawJWKSet), &jwkset); err != nil {
		t.Fatal(err)
	}
	t.Log(jwkset["keys"])
}
