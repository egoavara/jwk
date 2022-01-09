package jwk_test

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/egoavara/jwk"
	"github.com/golang-jwt/jwt/v4"
)

func TestGolangJWT(t *testing.T) {
	t.Run("RS256", func(t *testing.T) {
		rkey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		prik := jwk.MustKey(rkey, jwk.AlgorithmRS256)
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

}
