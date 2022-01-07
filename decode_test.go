package jwk_test

import (
	"context"
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

// test utils
var (
	//go:embed embeding/key-invalid.txt
	keyInvalid string
	//go:embed embeding/set-for-selector.json
	setForSelector string
)

// base key fields
var (
	//go:embed embeding/basekey-kty-not-exist.json
	basekeyKtyNotExist string
	//go:embed embeding/basekey-kty-not-string.json
	basekeyKtyNotString string

	//go:embed embeding/basekey-use-valid.json
	basekeyUseValid string
	//go:embed embeding/basekey-use-untype.json
	basekeyUseUntype string
	//go:embed embeding/basekey-use-unknown.json
	basekeyUseUnknown string

	//go:embed embeding/basekey-key_ops-valid.json
	basekeyKeyOpsValid string
	//go:embed embeding/basekey-key_ops-untype.json
	basekeyKeyOpsUntype string
	//go:embed embeding/basekey-key_ops-unknown.json
	basekeyKeyOpsUnknown string
	//go:embed embeding/basekey-key_ops-duplicated.json
	basekeyKeyOpsDuplicated string
	//go:embed embeding/basekey-key_ops-combination.json
	basekeyKeyOpsCombination string

	//go:embed embeding/basekey-both-use-keyops-valid.json
	basekeyBothUseKeyopsValid string
	//go:embed embeding/basekey-both-use-keyops-invalid.json
	basekeyBothUseKeyopsInvalid string

	//go:embed embeding/basekey-alg-valid.json
	basekeyAlgValid string
	//go:embed embeding/basekey-alg-untype.json
	basekeyAlgUntype string
	//go:embed embeding/basekey-alg-unknown.json
	basekeyAlgUnknown string

	//go:embed embeding/basekey-kid-valid.json
	basekeyKidValid string
	//go:embed embeding/basekey-kid-untype.json
	basekeyKidUntype string

	//go:embed embeding/basekey-x5u-type.json
	basekeyX5uType string
	//go:embed embeding/basekey-x5u-unurl.json
	basekeyX5uUnurl string
	//go:embed embeding/basekey-x5u-untype.json
	basekeyX5uUntype string

	//go:embed embeding/basekey-x5c-tempvalid.json
	basekeyX5cValid string
	//go:embed embeding/basekey-x5c-untype.json
	basekeyX5cUntype string
	//go:embed embeding/basekey-x5c-b64.json
	basekeyX5cB64 string
	//go:embed embeding/basekey-x5c-x509.json
	basekeyX5cX509 string

	//go:embed embeding/basekey-x5t-tempvalid.json
	basekeyX5tValid string
	//go:embed embeding/basekey-x5t-invalid-size.json
	basekeyX5tInvalidSize string
	//go:embed embeding/basekey-x5t-not-string.json
	basekeyX5tNotString string
	//go:embed embeding/basekey-x5t-not-b64.json
	basekeyX5tNotB64 string

	//go:embed embeding/basekey-x5ts256-tempvalid.json
	basekeyX5tS256Valid string
	//go:embed embeding/basekey-x5ts256-invalid-size.json
	basekeyX5tS256InvalidSize string
	//go:embed embeding/basekey-x5ts256-not-string.json
	basekeyX5tS256NotString string
	//go:embed embeding/basekey-x5ts256-not-b64.json
	basekeyX5tS256NotB64 string
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
	//go:embed embeding/ec-pri-not-string-d.json
	ecPriNotStringD string

	//go:embed embeding/ec-pri-invalid-length-d.json
	ecPriInvalidLengthD string
	//go:embed embeding/ec-pri-invalid-length-y.json
	ecPriInvalidLengthY string
	//go:embed embeding/ec-pri-invalid-length-x.json
	ecPriInvalidLengthX string
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

// Set
var (
	//go:embed embeding/set-unknown-field.json
	setUnknownField string
	//go:embed embeding/set-invalid-json.txt
	setInvalidJSON string
	//go:embed embeding/set-with-invalid-key.json
	setWithInvalidKey string
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
func TestDecodeKeySecrets(t *testing.T) {
	t.Run("nil source", func(t *testing.T) {
		_, err := jwk.DecodeKey(nil)
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrNil) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrNil)
		}
	})
	t.Run("done context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := jwk.DecodeKeyBy(ctx, strings.NewReader(rsaPriValid))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrContextDone) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrContextDone)
		}
	})
	t.Run("invalid json", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(keyInvalid))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidJSON) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidJSON)
		}
	})
	t.Run("not exist", func(t *testing.T) {
		var uk = new(jwk.UnknownKey)
		err := uk.UnmarshalJSON([]byte(rsaPriValid))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
	})
	t.Run("unmatched type", func(t *testing.T) {
		var ecprik = new(jwk.ECPrivateKey)
		err := ecprik.UnmarshalJSON([]byte(rsaPriValid))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrNotExpectedKty) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrNotExpectedKty)
		}
	})
	t.Run("from set", func(t *testing.T) {
		order := []jwk.Key{
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "A"}, KeyType: jwk.KeyTypeEC},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "B"}, KeyType: jwk.KeyTypeEC},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "B"}, KeyType: jwk.KeyTypeRSA},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "C"}, KeyType: jwk.KeyTypeEC},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "D"}, KeyType: jwk.KeyTypeEC},
		}
		_, err := jwk.DecodeKey(strings.NewReader(setForSelector), jwk.WithSelector(func(k jwk.Key) bool {
			if len(order) == 0 {
				t.Fatalf("unexpected key %v", k)
			}
			if !(order[0].Kid() == k.Kid() && order[0].Kty() == k.Kty()) {
				t.Fatalf("expected { kid:%v, kty:%v }, but got key { kid:%v, kty:%v }", order[0].Kid(), order[0].Kty(), k.Kid(), k.Kty())
			}
			if len(order) == 1 {
				return true
			}
			order = order[1:]
			return false
		}))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
	})
	t.Run("from invalid set", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(rsaPriInvalid), jwk.WithSelector(func(k jwk.Key) bool {
			return false
		}))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
	})
	t.Run("from set, but never select", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(setForSelector), jwk.WithSelector(func(k jwk.Key) bool {
			return false
		}))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrNoSelectedKey) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrNoSelectedKey)
		}
	})
}

func TestDecodeKty(t *testing.T) {
	t.Run("not exist", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyKtyNotExist))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrNotExist) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrNotExist)
		}
	})
	t.Run("not string", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyKtyNotString))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidString) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidString)
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

func TestDecodeKeyOps(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(basekeyKeyOpsValid))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if !k.KeyOps().In(jwk.KeyOpSign) {
			t.Fatalf("expected in %v, but not", jwk.KeyOpSign)
		}
	})
	t.Run("untype", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyKeyOpsUntype))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidArrayString) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidArrayString)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyKeyOpsUnknown), jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) {
			value.DisallowUnknownOp = true
		}))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrDisallowUnknownOp) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrDisallowUnknownOp)
		}
	})
	t.Run("duplicated", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyKeyOpsDuplicated), jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) {
			value.DisallowDuplicatedOps = true
		}))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrDisallowDuplicatedOps) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrDisallowDuplicatedOps)
		}
	})
	t.Run("combination", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyKeyOpsCombination), jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) {}))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidCombination) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidCombination)
		}
	})
}

func TestDecodeBothUseKeyOps(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyBothUseKeyopsValid))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
	})
	t.Run("disallow", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyBothUseKeyopsValid), jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) {
			value.DisallowBothUseAndOps = true
		}))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrDisallowBothUseKeyops) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrDisallowBothUseKeyops)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyBothUseKeyopsInvalid))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrNotCompatible) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrNotCompatible)
		}
	})
}

func TestDecodeAlg(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(basekeyAlgValid))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if k.Alg() != jwk.AlgorithmHS256 {
			t.Fatalf("expected %v, but got %v", jwk.AlgorithmHS256, k.Alg())
		}
	})
	t.Run("untype", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyAlgUntype))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidString) {
			t.Fatalf("expected %v is %v, but got", err, jwk.ErrInvalidString)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyAlgUnknown), jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) {
			value.DisallowUnknownAlgorithm = true
		}))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrDisallowUnknownAlgorithm) {
			t.Fatalf("expected %v is %v, but got", err, jwk.ErrInvalidString)
		}
	})
}

func TestDecodeKid(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(basekeyKidValid))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if k.Kid() != "id" {
			t.Fatalf("expected 'id', but got %v", k.Kid())
		}
	})
	t.Run("untype", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyKidUntype))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidString) {
			t.Fatalf("expected %v is %v, but got", err, jwk.ErrInvalidString)
		}
	})
}

func TestDecodeX5u(t *testing.T) {
	// TODO : Check validate
	t.Run("type", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(basekeyX5uType))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if k.X5u().String() != "https://github.com/iamGreedy" {
			t.Fatalf("expected '%v', but got '%v'", "https://github.com/iamGreedy", k.X5u().String())
		}
	})
	t.Run("unurl", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5uUnurl))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidURL) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidURL)
		}
	})
	t.Run("untype", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5uUntype))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidString) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidURL)
		}
	})
}

func TestDecodeX5c(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5cValid))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
	})
	t.Run("x509", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5cX509))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidX509) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidX509)
		}
	})
	t.Run("untype", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5cUntype))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidArrayString) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidX509)
		}
	})
	t.Run("base64", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5cB64))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidBase64) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidX509)
		}
	})
}

func TestDecodeX5t(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5tValid))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		// TODO : Check validate
	})
	t.Run("not string", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5tNotString))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidString) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidString)
		}
	})
	t.Run("not b64", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5tNotB64))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidBase64) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidBase64)
		}
	})
	t.Run("invalid size", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5tInvalidSize))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrSHA1Size) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrSHA1Size)
		}
	})
}

func TestDecodeX5tS256(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5tS256Valid))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		// TODO : Check validate
	})
	t.Run("not string", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5tS256NotString))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidString) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidString)
		}
	})
	t.Run("not b64", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5tS256NotB64))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidBase64) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidBase64)
		}
	})
	t.Run("invalid size", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5tS256InvalidSize))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrSHA256Size) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrSHA256Size)
		}
	})
}

func TestDecodeX5tSHA256(t *testing.T) {

	t.Run("valid", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5tValid))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		// TODO : Check validate
	})
	t.Run("not string", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5tNotString))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidString) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidString)
		}
	})
	t.Run("not b64", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5tNotB64))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrInvalidBase64) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidBase64)
		}
	})
	t.Run("invalid size", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(basekeyX5tInvalidSize))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrSHA1Size) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInvalidBase64)
		}
	})
}

func TestDecodeUnknown(t *testing.T) {
	t.Run("unknown kty", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(unknownUnknownKty))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if k.Kty() != "unknown" {
			t.Fatalf("expected %v, but got %v", "unknown", k.Kty())
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
	t.Run("not string d", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(ecPriNotStringD))
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

	t.Run("invalid length x", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(ecPriInvalidLengthX))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrECInvalidBytesLength) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrECInvalidBytesLength)
		}
	})
	t.Run("invalid length y", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(ecPriInvalidLengthY))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrECInvalidBytesLength) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrECInvalidBytesLength)
		}
	})
	t.Run("invalid length d", func(t *testing.T) {
		_, err := jwk.DecodeKey(strings.NewReader(ecPriInvalidLengthD))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrECInvalidBytesLength) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrECInvalidBytesLength)
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

func TestDecodeSet(t *testing.T) {
	t.Run("invalid json", func(t *testing.T) {
		_, err := jwk.DecodeSet(strings.NewReader(setInvalidJSON))
		if !errors.Is(err, jwk.ErrInvalidJSON) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrContextDone)
		}
	})
	t.Run("with invalid key", func(t *testing.T) {
		_, err := jwk.DecodeSet(strings.NewReader(setWithInvalidKey))
		if !errors.Is(err, jwk.ErrInnerKey) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrInnerKey)
		}
	})
	t.Run("done context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := jwk.DecodeSetBy(ctx, strings.NewReader(setUnknownField))
		if !errors.Is(err, jwk.ErrContextDone) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrContextDone)
		}
	})
	t.Run("allow unknown field", func(t *testing.T) {
		s, err := jwk.DecodeSet(strings.NewReader(setUnknownField), jwk.WithOptionDecodeSet(func(value *jwk.OptionDecodeSet) {
			value.DisallowUnknownField = false
		}))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if v, ok := s.Extra["unknown"]; ok {
			if v != "unknown" {
				t.Fatalf("expected Extra['unknown'] is %v, but got %v", "unknown", v)
			}
		} else {
			t.Fatalf("expected 'unknown' in Extra, but not")
		}
	})
	t.Run("disallow unknown field", func(t *testing.T) {
		_, err := jwk.DecodeSet(strings.NewReader(setUnknownField), jwk.WithOptionDecodeSet(func(value *jwk.OptionDecodeSet) {
			value.DisallowUnknownField = true
		}))
		if err == nil {
			t.Fatalf("expected not <nil>, but got <nil>")
		}
		if !errors.Is(err, jwk.ErrDisallowUnkwownField) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrDisallowUnkwownField)
		}
	})
}
