package jwk_test

import (
	_ "embed"
	"errors"
	"strings"
	"testing"

	"github.com/egoavara/jwk"
)

//go:embed embeding/set-with-invalid-key.json
var srcErrors string

func TestError(t *testing.T) {
	expectedFe := jwk.FieldError("keys")
	expectedIe := jwk.IndexError(0)
	_, err := jwk.DecodeSet(strings.NewReader(srcErrors))
	if !errors.Is(err, expectedFe) {
		t.Fatalf("expected %v is %v, but not", err, expectedFe)
	}
	if !errors.Is(err, expectedIe) {
		t.Fatalf("expected %v is %v, but not", err, expectedIe)
	}
	var fe jwk.FieldError
	var ie jwk.IndexError
	if !errors.As(err, &fe) {
		t.Fatalf("expected %v as %T, but not", err, fe)
	} else if !fe.Is(expectedFe) {
		t.Fatalf("expected %v is %v, but not", err, expectedFe)
	} else if !fe.Is(&expectedFe) {
		t.Fatalf("expected %v is %v, but not", err, &expectedFe)
	} else if fe.Is(nil) {
		t.Fatalf("expected %v is not %v, but not", err, nil)
	}
	if !errors.As(err, &ie) {
		t.Fatalf("expected %v as %T, but not", err, ie)
	} else if !ie.Is(expectedIe) {
		t.Fatalf("expected %v is %v, but not", err, expectedIe)
	} else if !ie.Is(&expectedIe) {
		t.Fatalf("expected %v is %v, but not", err, &expectedIe)
	} else if ie.Is(nil) {
		t.Fatalf("expected %v is not %v, but not", err, nil)
	}

	if fe.Error() != "'keys'" {
		t.Fatalf("expected %s, but got %s", fe.Error(), "'keys'")
	}
	if ie.Error() != "[0]" {
		t.Fatalf("expected %s, but got %s", fe.Error(), "[0]")
	}
	errmsg := "inner key failed, 'keys', [0], not satisfied requirement, ec public key failed, 'crv', not exist"
	if err.Error() != errmsg {
		t.Fatalf("expected %s, but got %s", err.Error(), errmsg)
	}
}
