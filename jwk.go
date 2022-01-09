package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/url"
)

// Set is JWK Set struct
// https://datatracker.ietf.org/doc/html/rfc7517#section-5
type Set struct {
	Keys  []Key // https://datatracker.ietf.org/doc/html/rfc7517#section-5.1
	Extra map[string]interface{}
}

// Key is JWK Key struct
// https://datatracker.ietf.org/doc/html/rfc7517#section-4
type Key interface {
	json.Marshaler
	json.Unmarshaler
	Kty() KeyType
	Use() KeyUse
	KeyOps() KeyOps
	Alg() Algorithm
	Kid() string
	X5u() *url.URL
	X5c() []*x509.Certificate
	X5t() []byte
	X5tS256() []byte
	Extra() map[string]interface{}
	//
	IntoKey() interface{}
	IntoPublicKey() crypto.PublicKey
	IntoPrivateKey() crypto.PrivateKey
	//
	intoUnknown() *UnknownKey
	intoBaseKey() *BaseKey
}

type (
	BaseKey struct {
		// KeyType not required : implementation reason. : https://datatracker.ietf.org/doc/html/rfc7517#section-4.2
		KeyUse                 KeyUse                 // https://datatracker.ietf.org/doc/html/rfc7517#section-4.2
		KeyOperations          KeyOps                 // https://datatracker.ietf.org/doc/html/rfc7517#section-4.3
		Algorithm              Algorithm              // https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
		KeyID                  string                 // https://datatracker.ietf.org/doc/html/rfc7517#section-4.5
		X509URL                *url.URL               // https://datatracker.ietf.org/doc/html/rfc7517#section-4.6
		X509CertChain          []*x509.Certificate    // https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
		X509CertThumbprint     []byte                 // https://datatracker.ietf.org/doc/html/rfc7517#section-4.8
		X509CertThumbprintS256 []byte                 // https://datatracker.ietf.org/doc/html/rfc7517#section-4.9
		extra                  map[string]interface{} // extra fields for Key
	}
	UnknownKey struct {
		BaseKey
		KeyType KeyType
	}

	// https://www.rfc-editor.org/rfc/rfc7518#section-3
	RSAPrivateKey struct {
		BaseKey
		Key *rsa.PrivateKey
	}
	// https://www.rfc-editor.org/rfc/rfc7518#section-3
	RSAPublicKey struct {
		BaseKey
		Key *rsa.PublicKey
	}
	// https://www.rfc-editor.org/rfc/rfc7518#section-3
	ECPrivateKey struct {
		BaseKey
		Key *ecdsa.PrivateKey
	}
	// https://www.rfc-editor.org/rfc/rfc7518#section-3
	ECPublicKey struct {
		BaseKey
		Key *ecdsa.PublicKey
	}
	// https://www.rfc-editor.org/rfc/rfc7518#section-3
	SymetricKey struct {
		BaseKey
		Key []byte
	}
	// TODO : https://www.rfc-editor.org/rfc/rfc7518#section-4
	// TODO : https://www.rfc-editor.org/rfc/rfc7518#section-5
)

type (
	OptionalNewKey interface {
		WithNewKey(Key, *BaseKey) error
	}
	WithAlgorithm Algorithm
)

// data is one of
// - *rsa.PrivateKey	-> *RSAPrivateKey
// - *rsa.PublicKey		-> *RSAPublicKey
// - *ecdsa.PrivateKey	-> *ECPrivateKey
// - *ecdsa.PublicKey	-> *ECPublicKey
// - []byte				-> *SymetricKey
// - string				-> *SymetricKey
// - Key				-> (self)
func NewKey(data interface{}, options ...OptionalNewKey) (Key, error) {
	var result Key
	switch d := data.(type) {
	case *rsa.PrivateKey:
		result = &RSAPrivateKey{
			BaseKey: BaseKey{
				KeyOperations: map[KeyOp]struct{}{},
				extra:         map[string]interface{}{},
			},
			Key: d,
		}
	case *rsa.PublicKey:
		result = &RSAPublicKey{
			BaseKey: BaseKey{
				KeyOperations: map[KeyOp]struct{}{},
				extra:         map[string]interface{}{},
			},
			Key: d,
		}
	case *ecdsa.PrivateKey:
		result = &ECPrivateKey{
			BaseKey: BaseKey{
				KeyOperations: map[KeyOp]struct{}{},
				extra:         map[string]interface{}{},
			},
			Key: d,
		}
	case *ecdsa.PublicKey:
		result = &ECPublicKey{
			BaseKey: BaseKey{
				KeyOperations: map[KeyOp]struct{}{},
				extra:         map[string]interface{}{},
			},
			Key: d,
		}
	case []byte:
		result = &SymetricKey{
			BaseKey: BaseKey{
				KeyOperations: map[KeyOp]struct{}{},
				extra:         map[string]interface{}{},
			},
			Key: d,
		}
	case string:
		result = &SymetricKey{
			BaseKey: BaseKey{
				KeyOperations: map[KeyOp]struct{}{},
				extra:         map[string]interface{}{},
			},
			Key: []byte(d),
		}
	case Key:
		result = d
	default:
		return nil, ErrIncompatibleType
	}
	for i, opt := range options {
		if err := opt.WithNewKey(result, result.intoBaseKey()); err != nil {
			return nil, makeErrors(IndexError(i), err)
		}
	}
	return result, nil
}

func MustKey(data interface{}, options ...OptionalNewKey) Key {
	k, err := NewKey(data, options...)
	if err != nil {
		return nil
	}
	return k
}
func NewSet(keys ...Key) *Set {
	return &Set{
		Keys:  keys,
		Extra: make(map[string]interface{}),
	}
}

//
func (set *Set) GetKey(kid string) Key {
	for _, k := range set.Keys {
		if k.Kid() == kid {
			return k
		}
	}
	return nil
}
func (set *Set) GetKeys(kid string) []Key {
	res := make([]Key, 0, 1)
	for _, k := range set.Keys {
		if k.Kid() == kid {
			res = append(res, k)
		}
	}
	return res
}
func (set *Set) GetUniqueKey(kid string, kty KeyType) Key {
	for _, k := range set.Keys {
		if k.Kid() == kid && k.Kty() == kty {
			return k
		}
	}
	return nil
}

func (alg Algorithm) WithNewKey(k Key, bk *BaseKey) error {
	if alg.IntoKeyType() == k.Kty() {
		bk.Algorithm = alg
		return nil
	}
	return ErrIncompatibleAlgorithm
}
func (w WithAlgorithm) WithNewKey(k Key, bk *BaseKey) error {
	alg := Algorithm(w)
	if alg.IntoKeyType() == k.Kty() {
		bk.Algorithm = alg
		return nil
	}
	return ErrIncompatibleAlgorithm
}
