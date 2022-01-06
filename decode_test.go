package jwk_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/egoavara/jwk"
)

// base key fields
var (
	//go:embed embeding/basekey-use-valid.json
	basekeyUseValid string
	//go:embed embeding/basekey-use-untype.json
	basekeyUseUntype string
	//go:embed embeding/basekey-use-unknown.json
	basekeyUseUnknown string
)

// Unknown key
var (
	//go:embed embeding/unknown-unknown-kty.json
	unknownUnknownKty string
)

// octet(Symetric) key
var (
	//go:embed embeding/octet-valid.json
	octetValid string
	//go:embed embeding/octet-without-k.json
	octetWithoutK string
)

// EC public key
var (
	//go:embed embeding/ec-pub-valid.json
	ecPubValid string
	//go:embed embeding/ec-pub-unknown-crv.json
	ecPubUnknownCrv string
	//go:embed embeding/ec-pub-without-crv.json
	ecPubWithoutCrv string
	//go:embed embeding/ec-pub-without-x.json
	ecPubWithoutX string
	//go:embed embeding/ec-pub-without-y.json
	ecPubWithoutY string
)

// EC private key
var (
	//go:embed embeding/ec-pri-valid.json
	ecPriValid string
	//go:embed embeding/ec-pri-valid-p384.json
	ecPriValidP384 string
	//go:embed embeding/ec-pri-valid-p521.json
	ecPriValidP521 string
	//go:embed embeding/ec-pri-unknown-crv.json
	ecPriUnknownCrv string
	//go:embed embeding/ec-pri-without-crv.json
	ecPriWithoutCrv string
	//go:embed embeding/ec-pri-without-x.json
	ecPriWithoutX string
	//go:embed embeding/ec-pri-without-y.json
	ecPriWithoutY string
	//go:embed embeding/ec-pri-invalid-d.json
	ecPriInvalidD string
)

// RSA public key
var (
	//go:embed embeding/rsa-pub-valid.json
	rsaPubValid string
	//go:embed embeding/rsa-pub-without-n.json
	rsaPubWithoutN string
	//go:embed embeding/rsa-pub-without-e.json
	rsaPubWithoutE string
)

// RSA public key
var (
	//go:embed embeding/rsa-pri-valid.json
	rsaPriValid string
	//go:embed embeding/rsa-pri-invalid.json
	rsaPriInvalid string
	//go:embed embeding/rsa-pri-without-n.json
	rsaPriWithoutN string
	//go:embed embeding/rsa-pri-without-e.json
	rsaPriWithoutE string
	//go:embed embeding/rsa-pri-invalid-b64-d.json
	rsaPriInvalidB64D string
	//go:embed embeding/rsa-pri-without-d.json
	rsaPriWithoutD string
	//go:embed embeding/rsa-pri-without-p.json
	rsaPriWithoutP string
	//go:embed embeding/rsa-pri-without-q.json
	rsaPriWithoutQ string
	//go:embed embeding/rsa-pri-without-dp.json
	rsaPriWithoutDp string
	//go:embed embeding/rsa-pri-without-dq.json
	rsaPriWithoutDq string
	//go:embed embeding/rsa-pri-without-qi.json
	rsaPriWithoutQi string
	//go:embed embeding/rsa-pri-no-precomputed.json
	rsaPriNoPrecomputed string
)

func withoutField(fieldname string, t *testing.T, file io.Reader) {
	t.Run(fmt.Sprintf("without '%s'", fieldname), func(t *testing.T) {
		_, err := jwk.DecodeKey(file)
		if err == nil {
			t.Fatalf("expected value not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrRequirement) {
			t.Fatalf("expected error is %v, but not", jwk.ErrRequirement)
		}
		if !errors.Is(err, jwk.FieldError(fieldname)) {
			t.Fatalf("expected %v is %v, but not", err, jwk.FieldError(fieldname))
		}
	})
}

func TestDecodeUse(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(basekeyUseValid))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if k.Use() != jwk.KeyUseSig {
			t.Fatalf("expected %v, but got %v", jwk.KeyUseSig, k.Use())
		}
	})
	t.Run("untype", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyUseUntype))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidString) {
			t.Fatalf("expected %v is %v, but got", err, jwk.ErrInvalidString)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyUseUnknown), jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) {
			value.DisallowUnknownUse = true
		}))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrUnknownKeyUse) {
			t.Fatalf("expected %v is %v, but got", err, jwk.ErrUnknownKeyUse)
		}
	})
}
func TestDecodeUnknown(t *testing.T) {
	t.Run("unknown kty", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(unknownUnknownKty))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if _, ok := k.(*jwk.UnknownKey); !ok {
			t.Fatalf("expected %T, but got %T", new(jwk.UnknownKey), k)
		}
	})
}

func TestDecodeOctet(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(octetValid))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if k.Kty() != jwk.KeyTypeOctet {
			t.Fatalf("expected %v, but got %v", jwk.KeyTypeOctet, k.Kty())
		}
	})
	//

	t.Run("k", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(octetWithoutK))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrRequirement) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrRequirement)
		}
		if !errors.Is(err, jwk.ErrCauseSymetricKey) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrCauseSymetricKey)
		}
		if !errors.Is(err, jwk.FieldError("k")) {
			t.Fatalf("expected %v is %v, but not", err, jwk.FieldError("k"))
		}
	})
}

func TestDecodeECPri(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(ecPriValid))
		if err != nil {
			t.Fatalf("expected value <nil>, but got %v", err)
		}
		if k.Kty() != jwk.KeyTypeEC {
			t.Fatalf("expected value %v, but got %v", jwk.KeyTypeEC, k.Kty())
		}
	})
	t.Run("valid P-384", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(ecPriValidP384))
		if err != nil {
			t.Fatalf("expected value <nil>, but got %v", err)
		}
		if k.Kty() != jwk.KeyTypeEC {
			t.Fatalf("expected value %v, but got %v", jwk.KeyTypeEC, k.Kty())
		}
		if pubk, ok := k.IntoPublicKey().(*ecdsa.PublicKey); ok {
			if pubk.Curve.Params().Name != "P-384" {
				t.Fatalf("expected value %v, but got %v", pubk.Curve.Params().Name, "P-384")
			}
		} else {
			t.Fatalf("expected value %T, but got %T", new(ecdsa.PublicKey), k.IntoPublicKey())
		}
	})
	t.Run("valid P-521", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(ecPriValidP521))
		if err != nil {
			t.Fatalf("expected value <nil>, but got %v", err)
		}
		if k.Kty() != jwk.KeyTypeEC {
			t.Fatalf("expected value %v, but got %v", jwk.KeyTypeEC, k.Kty())
		}
		if pubk, ok := k.IntoPublicKey().(*ecdsa.PublicKey); ok {
			if pubk.Curve.Params().Name != "P-521" {
				t.Fatalf("expected value %v, but got %v", pubk.Curve.Params().Name, "P-521")
			}
		} else {
			t.Fatalf("expected value %T, but got %T", new(ecdsa.PublicKey), k.IntoPublicKey())
		}
	})
	withoutField("crv", t, strings.NewReader(ecPriWithoutCrv))
	withoutField("x", t, strings.NewReader(ecPriWithoutX))
	withoutField("y", t, strings.NewReader(ecPriWithoutY))
	t.Run("unknown crv", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(ecPriUnknownCrv))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrCauseECPrivateKey) {
			t.Fatalf("expected is jwk.ErrCauseECPrivateKey")
		}
		if !errors.Is(err, jwk.FieldError("crv")) {
			t.Fatalf("expected is jwk.FieldError('crv')")
		}
		if !errors.Is(err, jwk.ErrCauseUnknown) {
			t.Fatalf("expected is jwk.ErrCauseUnknown")
		}
	})
	t.Run("invalid d", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(ecPriInvalidD))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrCauseECPrivateKey) {
			t.Fatalf("expected is jwk.ErrCauseECPrivateKey")
		}
		if !errors.Is(err, jwk.FieldError("d")) {
			t.Fatalf("expected is jwk.FieldError('crv')")
		}
		if !errors.Is(err, jwk.ErrInvalidBase64) {
			t.Fatalf("expected is jwk.ErrCauseUnknown")
		}
	})
}

func TestDecodeECPub(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(ecPubValid))
		if err != nil {
			t.Fatalf("expected value <nil>, but got %v", err)
		}
		if k.Kty() != jwk.KeyTypeEC {
			t.Fatalf("expected value %v, but got %v", jwk.KeyTypeEC, k.Kty())
		}
	})
	withoutField("crv", t, strings.NewReader(ecPubWithoutCrv))
	withoutField("x", t, strings.NewReader(ecPubWithoutX))
	withoutField("y", t, strings.NewReader(ecPubWithoutY))
	t.Run("unknown crv", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(ecPubUnknownCrv))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrCauseECPublicKey) {
			t.Fatalf("expected is jwk.ErrCauseECPublicKey")
		}
		if !errors.Is(err, jwk.FieldError("crv")) {
			t.Fatalf("expected is jwk.FieldError('crv')")
		}
		if !errors.Is(err, jwk.ErrCauseUnknown) {
			t.Fatalf("expected is jwk.ErrCauseUnknown")
		}
	})
}

func TestDecodeRSAPub(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(rsaPubValid))
		if err != nil {
			t.Fatalf("expected value <nil>, but got %v", err)
		}
		if k.Kty() != jwk.KeyTypeRSA {
			t.Fatalf("expected value %v, but got %v", jwk.KeyTypeRSA, k.Kty())
		}
	})
	withoutField("n", t, strings.NewReader(rsaPubWithoutN))
	withoutField("e", t, strings.NewReader(rsaPubWithoutE))
}

func TestDecodeRSAPri(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(rsaPriValid))
		if err != nil {
			t.Fatalf("expected value <nil>, but got %v", err)
		}
		if k.Kty() != jwk.KeyTypeRSA {
			t.Fatalf("expected value %v, but got %v", jwk.KeyTypeRSA, k.Kty())
		}
	})
	withoutField("n", t, strings.NewReader(rsaPriWithoutN))
	withoutField("e", t, strings.NewReader(rsaPriWithoutE))
	t.Run("d", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(rsaPriWithoutD))
		if err == nil {
			t.Fatalf("expected value not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrDisallowUnkwownField) {
			t.Fatalf("expected error is %v, but not", jwk.ErrDisallowUnkwownField)
		}
	})
	t.Run("d", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(rsaPriInvalidB64D))
		if err == nil {
			t.Fatalf("expected value not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidBase64) {
			t.Fatalf("expected error is %v, but not", jwk.ErrDisallowUnkwownField)
		}
	})
	withoutField("p", t, strings.NewReader(rsaPriWithoutP))
	withoutField("q", t, strings.NewReader(rsaPriWithoutQ))
	withoutField("dp", t, strings.NewReader(rsaPriWithoutDp))
	withoutField("dq", t, strings.NewReader(rsaPriWithoutDq))
	withoutField("qi", t, strings.NewReader(rsaPriWithoutQi))
	// TODO : oth field testing
	t.Run("no precomputed", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(rsaPriNoPrecomputed))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		k0, err := jwk.DecodeKey(strings.NewReader(rsaPriNoPrecomputed), jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) {
			value.IgnorePrecomputed = true
		}))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		k1, err := jwk.DecodeKey(strings.NewReader(rsaPriValid), jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) {
			value.IgnorePrecomputed = true
		}))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		target, err := jwk.DecodeKey(strings.NewReader(rsaPriValid))

		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		pk0 := k0.IntoKey().(*rsa.PrivateKey)
		pk1 := k1.IntoKey().(*rsa.PrivateKey)
		pt := target.IntoKey().(*rsa.PrivateKey)

		if pk0.Precomputed.Dp.Cmp(pt.Precomputed.Dp) != 0 {
			t.Fatalf("expected %v, but got %v", pt.Precomputed.Dp, pk0.Precomputed.Dp)
		}
		if pk0.Precomputed.Dq.Cmp(pt.Precomputed.Dq) != 0 {
			t.Fatalf("expected %v, but got %v", pt.Precomputed.Dq, pk0.Precomputed.Dq)
		}
		if pk0.Precomputed.Qinv.Cmp(pt.Precomputed.Qinv) != 0 {
			t.Fatalf("expected %v, but got %v", pt.Precomputed.Qinv, pk0.Precomputed.Qinv)
		}
		if pk1.Precomputed.Dp.Cmp(pt.Precomputed.Dp) != 0 {
			t.Fatalf("expected %v, but got %v", pt.Precomputed.Dp, pk0.Precomputed.Dp)
		}
		if pk1.Precomputed.Dq.Cmp(pt.Precomputed.Dq) != 0 {
			t.Fatalf("expected %v, but got %v", pt.Precomputed.Dq, pk0.Precomputed.Dq)
		}
		if pk1.Precomputed.Qinv.Cmp(pt.Precomputed.Qinv) != 0 {
			t.Fatalf("expected %v, but got %v", pt.Precomputed.Qinv, pk0.Precomputed.Qinv)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(rsaPriInvalid))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
	})
}
