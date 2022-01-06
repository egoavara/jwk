package jwk

import (
	"bytes"
	"context"
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
	json.Marshaler
	json.Unmarshaler
	Keys  []Key // https://datatracker.ietf.org/doc/html/rfc7517#section-5.1
	Extra map[string]interface{}
}

// BaseKey is JWK BaseKey struct
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

func (key *UnknownKey) Kty() KeyType {
	return key.KeyType
}
func (key *RSAPrivateKey) Kty() KeyType {
	return KeyTypeRSA
}
func (key *RSAPublicKey) Kty() KeyType {
	return KeyTypeRSA
}
func (key *ECPrivateKey) Kty() KeyType {
	return KeyTypeEC
}
func (key *ECPublicKey) Kty() KeyType {
	return KeyTypeEC
}
func (key *SymetricKey) Kty() KeyType {
	return KeyTypeOctet
}

func (key *BaseKey) Use() KeyUse {
	return key.KeyUse
}

func (key *BaseKey) KeyOps() KeyOps {
	return key.KeyOperations
}

func (key *BaseKey) Alg() Algorithm {
	return key.Algorithm
}

func (key *BaseKey) Kid() string {
	return key.KeyID
}

func (key *BaseKey) X5u() *url.URL {
	return key.X509URL
}

func (key *BaseKey) X5c() []*x509.Certificate {
	return key.X509CertChain
}

func (key *BaseKey) X5t() []byte {
	return key.X509CertThumbprint
}

func (key *BaseKey) X5tS256() []byte {
	return key.X509CertThumbprintS256
}

func (key *BaseKey) Extra() map[string]interface{} {
	return key.extra
}

func (set *Set) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := EncodeSetBy(context.Background(), set, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (set *Set) UnmarshalJSON(bts []byte) error {
	rdr := bytes.NewReader(bts)
	dat, err := DecodeSetBy(context.Background(), rdr)
	if err != nil {
		return err
	}
	*set = *dat
	return nil
}

func (key *UnknownKey) intoUnknown() *UnknownKey {
	return key
}
func (key *UnknownKey) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := EncodeKeyBy(context.Background(), key, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (key *UnknownKey) UnmarshalJSON(bts []byte) error {
	rdr := bytes.NewReader(bts)
	var opt *OptionDecodeKey
	ctx := MustGetOptionFromContext(context.Background(), &opt, true)
	opt.forceUnknownKey = true
	dat, err := DecodeKeyBy(ctx, rdr)
	if err != nil {
		return err
	}
	*key = *(dat.intoUnknown())
	return nil
}

func (key *UnknownKey) IntoKey() interface{} {
	return nil
}

func (key *UnknownKey) IntoPublicKey() crypto.PublicKey {
	return nil
}

func (key *UnknownKey) IntoPrivateKey() crypto.PrivateKey {
	return nil
}

func (key *RSAPrivateKey) intoUnknown() *UnknownKey {
	res := new(UnknownKey)
	bts, _ := key.MarshalJSON()
	res.UnmarshalJSON(bts)
	// TODO : Fatal error?
	return res
}

func (key *RSAPrivateKey) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := EncodeKeyBy(context.Background(), key, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (key *RSAPrivateKey) UnmarshalJSON(bts []byte) error {
	rdr := bytes.NewReader(bts)
	var opt *OptionDecodeKey
	ctx := MustGetOptionFromContext(context.Background(), &opt, true)
	opt.constraintKeyType = KeyTypeRSA
	dat, err := DecodeKeyBy(ctx, rdr)
	if err != nil {
		return err
	}
	*key = *(dat.(*RSAPrivateKey))
	return nil
}

func (key *RSAPrivateKey) IntoKey() interface{} {
	return key.Key
}

func (key *RSAPrivateKey) IntoPublicKey() crypto.PublicKey {
	return key.Key.Public()
}

func (key *RSAPrivateKey) IntoPrivateKey() crypto.PrivateKey {
	return key.Key
}

func (key *RSAPublicKey) intoUnknown() *UnknownKey {
	res := new(UnknownKey)
	bts, _ := key.MarshalJSON()
	res.UnmarshalJSON(bts)
	// TODO : Fatal error?
	return res
}
func (key *RSAPublicKey) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := EncodeKeyBy(context.Background(), key, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func (key *RSAPublicKey) UnmarshalJSON(bts []byte) error {
	rdr := bytes.NewReader(bts)
	var opt *OptionDecodeKey
	ctx := MustGetOptionFromContext(context.Background(), &opt, true)
	opt.constraintKeyType = KeyTypeRSA
	dat, err := DecodeKeyBy(ctx, rdr)
	if err != nil {
		return err
	}
	*key = *(dat.(*RSAPublicKey))
	return nil
}

func (key *RSAPublicKey) IntoKey() interface{} {
	return key.Key
}

func (key *RSAPublicKey) IntoPublicKey() crypto.PublicKey {
	return key.Key
}

func (key *RSAPublicKey) IntoPrivateKey() crypto.PrivateKey {
	return nil
}

func (key *ECPrivateKey) intoUnknown() *UnknownKey {
	res := new(UnknownKey)
	bts, _ := key.MarshalJSON()
	res.UnmarshalJSON(bts)
	// TODO : Fatal error?
	return res
}

func (key *ECPrivateKey) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := EncodeKeyBy(context.Background(), key, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (key *ECPrivateKey) UnmarshalJSON(bts []byte) error {
	rdr := bytes.NewReader(bts)
	var opt *OptionDecodeKey
	ctx := MustGetOptionFromContext(context.Background(), &opt, true)
	opt.constraintKeyType = KeyTypeEC
	dat, err := DecodeKeyBy(ctx, rdr)
	if err != nil {
		return err
	}
	*key = *(dat.(*ECPrivateKey))
	return nil
}

func (key *ECPrivateKey) IntoKey() interface{} {
	return key.Key
}

func (key *ECPrivateKey) IntoPublicKey() crypto.PublicKey {
	return key.Key.Public()
}

func (key *ECPrivateKey) IntoPrivateKey() crypto.PrivateKey {
	return key.Key
}

func (key *ECPublicKey) intoUnknown() *UnknownKey {
	res := new(UnknownKey)
	bts, _ := key.MarshalJSON()
	res.UnmarshalJSON(bts)
	// TODO : Fatal error?
	return res
}

func (key *ECPublicKey) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := EncodeKeyBy(context.Background(), key, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (key *ECPublicKey) UnmarshalJSON(bts []byte) error {
	rdr := bytes.NewReader(bts)
	var opt *OptionDecodeKey
	ctx := MustGetOptionFromContext(context.Background(), &opt, true)
	opt.constraintKeyType = KeyTypeEC
	dat, err := DecodeKeyBy(ctx, rdr)
	if err != nil {
		return err
	}
	*key = *(dat.(*ECPublicKey))
	return nil
}
func (key *ECPublicKey) IntoKey() interface{} {
	return key.Key
}

func (key *ECPublicKey) IntoPublicKey() crypto.PublicKey {
	return key.Key
}

func (key *ECPublicKey) IntoPrivateKey() crypto.PrivateKey {
	return nil
}

func (key *SymetricKey) intoUnknown() *UnknownKey {
	res := new(UnknownKey)
	bts, _ := key.MarshalJSON()
	res.UnmarshalJSON(bts)
	// TODO : Fatal error?
	return res
}
func (key *SymetricKey) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := EncodeKeyBy(context.Background(), key, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (key *SymetricKey) UnmarshalJSON(bts []byte) error {
	rdr := bytes.NewReader(bts)
	var opt *OptionDecodeKey
	ctx := MustGetOptionFromContext(context.Background(), &opt, true)
	opt.constraintKeyType = KeyTypeOctet
	dat, err := DecodeKeyBy(ctx, rdr)
	if err != nil {
		return err
	}
	*key = *(dat.(*SymetricKey))
	return nil
}
func (key *SymetricKey) IntoKey() interface{} {
	return key.Key
}

func (key *SymetricKey) IntoPublicKey() crypto.PublicKey {
	return nil
}

func (key *SymetricKey) IntoPrivateKey() crypto.PrivateKey {
	return nil
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

// In RFC, key's `alg` header is optional
// So if there is no defined algorithm, you need to guess it is compatible algorithm
func IsCompatibleKey(key Key, alg Algorithm) bool {
	if len(alg) <= 0 {
		// TODO : panic?
		return false
	}
	if keyalg := key.Alg(); len(keyalg) > 0 {
		return keyalg == alg
	}
	// TODO : key check steps
	// if key.Kty() != alg.IntoKeyType() {
	// 	return false
	// }
	return false
}
