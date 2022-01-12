package jwk_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"reflect"
	"testing"

	"github.com/egoavara/jwk"
	"github.com/golang-jwt/jwt/v4"
)

func mustECDSA(curve elliptic.Curve) *ecdsa.PrivateKey {
	ekey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("expected <nil>, but got %v", err))
	}
	return ekey
}

func mustRSA() *rsa.PrivateKey {

	rkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("expected <nil>, but got %v", err))
	}
	return rkey
}
func checkJWT(t *testing.T, key jwk.Key) {
	var before = jwt.MapClaims{
		"Hello": "World",
	}
	var after jwt.MapClaims
	//
	_, signed, err := jwk.LetSign(key, before)
	if err != nil {
		t.Fatalf("expecte <nil>, but got %v", err)
	}
	_, err = jwk.LetVerify(signed, key, &after)
	if err != nil {
		t.Fatalf("expecte <nil>, but got %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("expected %v, but got %v", before, after)
	}
}
func TestGolangJWT(t *testing.T) {
	t.Run("without helper", func(t *testing.T) {
		prik := jwk.MustKey(mustRSA(), jwk.AlgorithmRS256)
		var before = jwt.MapClaims{
			"test": "data",
		}
		var after jwt.MapClaims
		//
		data := jwt.NewWithClaims(jwk.LetSigningMethod(prik), before)

		signed, err := data.SignedString(prik.IntoPrivateKey())
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		_, err = jwt.ParseWithClaims(signed, &after, jwk.LetKeyfunc(prik))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("expected %v, but got %v", before, after)
		}
	})

	t.Run("with sign helper", func(t *testing.T) {
		prik := jwk.MustKey(mustRSA(), jwk.AlgorithmRS256)
		var before = jwt.MapClaims{
			"test": "data",
		}
		var after jwt.MapClaims
		//
		_, signed, err := jwk.LetSign(prik, before)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		_, err = jwt.ParseWithClaims(signed, &after, jwk.LetKeyfunc(prik))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("expected %v, but got %v", before, after)
		}
	})

	t.Run("with verify helper", func(t *testing.T) {
		prik := jwk.MustKey(mustRSA(), jwk.AlgorithmRS256)
		var before = jwt.MapClaims{
			"test": "data",
		}
		var after jwt.MapClaims
		//
		data := jwt.NewWithClaims(jwk.LetSigningMethod(prik), before)
		signed, err := data.SignedString(prik.IntoPrivateKey())
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//

		_, err = jwk.LetVerify(signed, prik, &after)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("expected %v, but got %v", before, after)
		}
	})

	t.Run("with helper", func(t *testing.T) {
		prik := jwk.MustKey(mustRSA(), jwk.AlgorithmRS256)
		var before = jwt.MapClaims{
			"test": "data",
		}
		var after jwt.MapClaims
		//
		_, signed, err := jwk.LetSign(prik, before)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//

		_, err = jwk.LetVerify(signed, prik, &after)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("expected %v, but got %v", before, after)
		}
	})

	t.Run("RS256", func(t *testing.T) {
		key, err := jwk.NewKey(mustRSA(), jwk.AlgorithmRS256)
		if err != nil {
			t.Fatalf("expecte <nil>, but got %v", err)
		}
		checkJWT(t, key)
	})
	t.Run("RS384", func(t *testing.T) {
		key, err := jwk.NewKey(mustRSA(), jwk.AlgorithmRS384)
		if err != nil {
			t.Fatalf("expecte <nil>, but got %v", err)
		}
		checkJWT(t, key)
	})
	t.Run("RS512", func(t *testing.T) {
		key, err := jwk.NewKey(mustRSA(), jwk.AlgorithmRS512)
		if err != nil {
			t.Fatalf("expecte <nil>, but got %v", err)
		}
		checkJWT(t, key)
	})

	t.Run("HS256", func(t *testing.T) {
		key, err := jwk.NewKey("SECRETCODE", jwk.AlgorithmHS256)
		if err != nil {
			t.Fatalf("expecte <nil>, but got %v", err)
		}
		checkJWT(t, key)
	})
	t.Run("HS384", func(t *testing.T) {
		key, err := jwk.NewKey("SECRETCODE", jwk.AlgorithmHS384)
		if err != nil {
			t.Fatalf("expecte <nil>, but got %v", err)
		}
		checkJWT(t, key)
	})
	t.Run("HS512", func(t *testing.T) {
		key, err := jwk.NewKey("SECRETCODE", jwk.AlgorithmHS512)
		if err != nil {
			t.Fatalf("expecte <nil>, but got %v", err)
		}
		checkJWT(t, key)
	})

	t.Run("ES256", func(t *testing.T) {
		key, err := jwk.NewKey(mustECDSA(elliptic.P256()), jwk.AlgorithmES256)
		if err != nil {
			t.Fatalf("expecte <nil>, but got %v", err)
		}
		checkJWT(t, key)
	})
	t.Run("ES384", func(t *testing.T) {
		key, err := jwk.NewKey(mustECDSA(elliptic.P384()), jwk.AlgorithmES384)
		if err != nil {
			t.Fatalf("expecte <nil>, but got %v", err)
		}
		checkJWT(t, key)
	})
	t.Run("ES512", func(t *testing.T) {
		key, err := jwk.NewKey(mustECDSA(elliptic.P521()), jwk.AlgorithmES512)
		if err != nil {
			t.Fatalf("expecte <nil>, but got %v", err)
		}
		checkJWT(t, key)
	})

}
