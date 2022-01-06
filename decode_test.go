package jwk_test

import (
	_ "embed"
	"errors"
	"strings"
	"testing"

	"github.com/egoavara/jwk"
)

//go:embed embeding/rsa-pub-valid.json
var rsaPubValid string

//go:embed embeding/rsa-pub-without-n.json
var rsaPubWithoutN string

func TestDecode(t *testing.T) {
	t.Run("valid RSA public key", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(rsaPubValid))
		if err != nil {
			t.Fatalf("expected value <nil>, but got %v", err)
		}
		if k.Kty() != jwk.KeyTypeRSA {
			t.Fatalf("expected value %v, but got %v", jwk.KeyTypeRSA, k.Kty())
		}
	})

	t.Run("without 'n' RSA public key", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(rsaPubWithoutN))
		if err == nil {
			t.Fatalf("expected value not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrRequirement) {
			t.Fatalf("expected error is %v, but not", jwk.ErrRequirement)
		}
		if !errors.Is(err, jwk.FieldError("n")) {
			t.Fatalf("expected %v is %v, but not", err, jwk.FieldError("n"))
		}
	})
}
