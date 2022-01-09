package jwk_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/egoavara/jwk"
)

var (
	//go:embed embeding/ec-pri-valid.json
	encECPri string
	//go:embed embeding/ec-pub-valid.json
	encECPub string

	//go:embed embeding/rsa-pri-valid.json
	encRSAPri string
	//go:embed embeding/rsa-pub-valid.json
	encRSAPub string

	//go:embed embeding/octet-valid.json
	encOctet string

	//go:embed embeding/basekey-all.json
	encBasekeyAll string
)

func TestEncodeKey(t *testing.T) {
	t.Run("ec private key", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(encECPri))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		kenc := bytes.NewBuffer(nil)
		if err := jwk.EncodeKey(k, kenc); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		var a map[string]interface{}
		var b map[string]interface{}
		if err := json.Unmarshal([]byte(encECPri), &a); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if err := json.Unmarshal(kenc.Bytes(), &b); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		if !reflect.DeepEqual(a, b) {
			ja, _ := json.MarshalIndent(a, "", "    ")
			jb, _ := json.MarshalIndent(b, "", "    ")
			t.Fatalf("expected %v equal %v, but not", string(ja), string(jb))
		}
	})

	t.Run("ec public key", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(encECPub))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		kenc := bytes.NewBuffer(nil)
		if err := jwk.EncodeKey(k, kenc); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		var a map[string]interface{}
		var b map[string]interface{}
		if err := json.Unmarshal([]byte(encECPub), &a); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if err := json.Unmarshal(kenc.Bytes(), &b); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		if !reflect.DeepEqual(a, b) {
			ja, _ := json.MarshalIndent(a, "", "    ")
			jb, _ := json.MarshalIndent(b, "", "    ")
			t.Fatalf("expected %v equal %v, but not", string(ja), string(jb))
		}
	})

	t.Run("rsa public key", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(encRSAPub))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		kenc := bytes.NewBuffer(nil)
		if err := jwk.EncodeKey(k, kenc); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		var a map[string]interface{}
		var b map[string]interface{}
		if err := json.Unmarshal([]byte(encRSAPub), &a); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if err := json.Unmarshal(kenc.Bytes(), &b); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		if !reflect.DeepEqual(a, b) {
			ja, _ := json.MarshalIndent(a, "", "    ")
			jb, _ := json.MarshalIndent(b, "", "    ")
			t.Fatalf("expected %v equal %v, but not", string(ja), string(jb))
		}
	})

	t.Run("rsa private key", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(encRSAPri))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		kenc := bytes.NewBuffer(nil)
		if err := jwk.EncodeKey(k, kenc); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		var a map[string]interface{}
		var b map[string]interface{}
		if err := json.Unmarshal([]byte(encRSAPri), &a); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if err := json.Unmarshal(kenc.Bytes(), &b); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		if !reflect.DeepEqual(a, b) {
			ja, _ := json.MarshalIndent(a, "", "    ")
			jb, _ := json.MarshalIndent(b, "", "    ")
			t.Fatalf("expected %v equal %v, but not", string(ja), string(jb))
		}
	})

	t.Run("symetric public key", func(t *testing.T) {
		k, err := jwk.DecodeKey(strings.NewReader(encOctet))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		kenc := bytes.NewBuffer(nil)

		if err := jwk.EncodeKey(k, kenc); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		var a map[string]interface{}
		var b map[string]interface{}
		if err := json.Unmarshal([]byte(encOctet), &a); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if err := json.Unmarshal(kenc.Bytes(), &b); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		if !reflect.DeepEqual(a, b) {
			ja, _ := json.MarshalIndent(a, "", "    ")
			jb, _ := json.MarshalIndent(b, "", "    ")
			t.Fatalf("expected %v equal %v, but not", string(ja), string(jb))
		}
	})

	t.Run("basekey", func(t *testing.T) {
		bcert, err := base64.RawStdEncoding.DecodeString(`MIIDazCCAlOgAwIBAgIUKAvNNGGWUrUKgLYZD3d+hpbBoT0wDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCS1IxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjAxMDYxMzE3MjBaFw0zMjAxMDQxMzE3MjBaMEUxCzAJBgNVBAYTAktSMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDXE/RPj9ej1gPtqBBMiN7XCqGdrXaw3ZKIAFHT8NIEJ7DklioJ/Nve+Fqp5yIbspoC8HGs8zxgIAGLyRY7WejLkZyplpTpA4PAHmK9ZRClbYFNoTaz733FNc/hqPMuMpwb1FPgR832lj/mEgxtMIaxrN3ZFlmknnWck9z+GEb4JA0AQOwpj85Eakc9EqTwSn7thgsQqPAT3ywX14kDVnSU+z2qLjmr6ocV78RPDaBgPcK/uzYu6VtPtlML2im3iijmHD8Z2LXOQwauX549A9icO/E02qyAz85/cDka8iEcUbwXEbRVnclii8LpfXIUKNZcCh6Cjr1FRIet+iNpyT9XAgMBAAGjUzBRMB0GA1UdDgQWBBTyRsAwPim3sjoo0qKSaUnfugmaXzAfBgNVHSMEGDAWgBTyRsAwPim3sjoo0qKSaUnfugmaXzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB+01IAp57m5oDB9RYB69qj6Isopd3AI2sh/NvAN+F8CQafPexq4eBo+iXvhMS5yu3NEn3wPzrX6RBGYnjq784jDp4nDOvNd9kE/6aj2IG5RM6tcilvhamy5/6d4cLE0Rg6rco6bEeLtu7IKKFZpW72STP3a36munv6dopZYtCeXTYQE8t0MKjBCcIksXHthnTfzOT8EhCAp1pYX23nq2sPfQNaNTYcQcVhyNqkyviPcrvnJnZUavzngMGajy+io2kRfLmPdzPUMmkfgacXxjsl5hI3jecmKzTTR3gOZvdgIgV2DJyYEs9/dKXIHL7o6D4j7cnTqRtQwoPlQEuuOJVD`)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		cert, err := x509.ParseCertificate(bcert)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		symk, err := base64.RawURLEncoding.DecodeString("GawgguFyGrWKav7AX4VKUg")
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		th, _ := base64.RawURLEncoding.DecodeString("bm90aGluZ3NwZWNpYWxpbmhlcmU")
		th256, _ := base64.RawURLEncoding.DecodeString("bm90aGluZ3NwZWNpYWxpbmhlcmVyZWFsbHlub3RoaW4")
		k := &jwk.SymetricKey{
			BaseKey: jwk.BaseKey{
				KeyUse: jwk.KeyUseSig,
				KeyOperations: jwk.KeyOps{
					jwk.KeyOpVerify: struct{}{},
				},
				Algorithm: jwk.AlgorithmHS256,
				KeyID:     "id",
				X509URL: &url.URL{
					Scheme:  "https",
					Host:    "github.com",
					Path:    "/iamGreedy",
					RawPath: "/iamGreedy",
				},
				X509CertChain:          []*x509.Certificate{cert},
				X509CertThumbprint:     th,
				X509CertThumbprintS256: th256,
			},
			Key: symk,
		}
		//
		kenc := bytes.NewBuffer(nil)
		if err := jwk.EncodeKey(k, kenc); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		a, err := jwk.DecodeKey(kenc)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		b, err := jwk.DecodeKey(strings.NewReader(encBasekeyAll))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		jsona, err := a.MarshalJSON()
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		jsonb, err := b.MarshalJSON()
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		var mapa map[string]interface{}
		var mapb map[string]interface{}
		if err := json.Unmarshal(jsona, &mapa); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if err := json.Unmarshal(jsonb, &mapb); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if !reflect.DeepEqual(mapa, mapb) {
			t.Fatalf("expected %v equal %v, but not", string(jsona), string(jsonb))

		}

	})

	t.Run("done context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		rkey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		key := jwk.MustKey(rkey)
		buf := bytes.NewBuffer(nil)
		if err := jwk.EncodeKeyBy(ctx, key, buf); !errors.Is(err, jwk.ErrContextDone) {
			t.Fatalf("expected <nil>, but got %v", err)
		}
	})

	t.Run("nil io", func(t *testing.T) {
		rkey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		key := jwk.MustKey(rkey)
		if err := jwk.EncodeKeyBy(context.Background(), key, nil); !errors.Is(err, jwk.ErrNil) {
			t.Fatalf("expected <nil>, but got %v", err)
		}
	})

	t.Run("nil key", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		if err := jwk.EncodeKeyBy(context.Background(), nil, buf); !errors.Is(err, jwk.ErrNil) {
			t.Fatalf("expected <nil>, but got %v", err)
		}
	})

	t.Run("extras", func(t *testing.T) {
		rkey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		var jsona = bytes.NewBuffer(nil)
		var jsonb = bytes.NewBuffer(nil)
		//
		key := jwk.MustKey(rkey)
		key.Extra()["hello"] = "world"

		if err = jwk.EncodeKey(key, jsona, jwk.WithOptionEncodeKey(func(value *jwk.OptionEncodeKey) { value.DisallowUnknownField = true })); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		if err := jwk.EncodeKey(key, jsonb); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		keya, err := jwk.DecodeKey(jsona, jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) {
			value.AllowUnknownField = true
		}))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		keyb, err := jwk.DecodeKey(jsonb, jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) {
			value.AllowUnknownField = true
		}))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		//
		if len(keya.Extra()) != 0 {
			t.Fatalf("expected empty, but got %v", keya)
		}
		if len(keyb.Extra()) != 1 {
			t.Fatalf("expected only one map, but got %d", len(keyb.Extra()))
		}
		if v, ok := keyb.Extra()["hello"]; ok {
			if v != "world" {
				t.Fatalf("expected not %v, but got %d", "world", v)
			}
		} else {
			t.Fatalf("expected not exist, but got %d", len(keyb.Extra()))
		}
	})

	t.Run("EC P-521, padding required", func(t *testing.T) {
		var eckey *ecdsa.PrivateKey
		var err error
		for eckey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); err == nil; eckey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader) {
			if len(eckey.X.Bytes()) != 66 {
				break
			}
			if len(eckey.Y.Bytes()) != 66 {
				break
			}
			if len(eckey.D.Bytes()) != 66 {
				break
			}
		}
		//
		k := jwk.MustKey(eckey)
		kenc := bytes.NewBuffer(nil)
		if err := jwk.EncodeKey(k, kenc); err != nil {
			t.Fatalf("expected not <nil>, but got %v", err)
		}
		//
		var jsonk map[string]interface{}
		if err := json.Unmarshal(kenc.Bytes(), &jsonk); err != nil {
			t.Fatalf("expected not <nil>, but got %v", err)
		}
		if base64.RawURLEncoding.DecodedLen(len(jsonk["x"].(string))) != 66 {
			t.Fatalf("expected 66 length bytes, but got %d length bytes", len(jsonk["x"].(string)))
		}
		if base64.RawURLEncoding.DecodedLen(len(jsonk["y"].(string))) != 66 {
			t.Fatalf("expected 66 length bytes, but got %d length bytes", len(jsonk["y"].(string)))
		}
		if base64.RawURLEncoding.DecodedLen(len(jsonk["d"].(string))) != 66 {
			t.Fatalf("expected 66 length bytes, but got %d length bytes", len(jsonk["d"].(string)))
		}
	})

}
func TestEncodeSet(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		eck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		k := jwk.MustKey(eck)
		s := jwk.NewSet(k)
		buf := bytes.NewBuffer(nil)
		if err := jwk.EncodeSet(s, buf, jwk.WithOptionEncodeSet(func(value *jwk.OptionEncodeSet) { value.DisallowUnknownField = true })); err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		sb, err := jwk.DecodeSet(buf)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if !reflect.DeepEqual(s, sb) {
			t.Fatalf("expected %#v equal %#v, but not", s, sb)
		}
	})

	t.Run("done context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		eck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		k := jwk.MustKey(eck)
		s := jwk.NewSet(k)
		buf := bytes.NewBuffer(nil)
		err := jwk.EncodeSetBy(ctx, s, buf)
		if !errors.Is(err, jwk.ErrContextDone) {
			t.Fatalf("expected %v, but got %v", err, jwk.ErrContextDone)
		}
	})

	t.Run("nil io", func(t *testing.T) {
		eck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		k := jwk.MustKey(eck)
		s := jwk.NewSet(k)
		err := jwk.EncodeSetBy(context.Background(), s, nil)
		if !errors.Is(err, jwk.ErrNil) {
			t.Fatalf("expected %v, but got %v", err, jwk.ErrNil)
		}
	})

	t.Run("nil set", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		err := jwk.EncodeSetBy(context.Background(), nil, buf)
		if !errors.Is(err, jwk.ErrNil) {
			t.Fatalf("expected %v, but got %v", err, jwk.ErrNil)
		}
	})
}
