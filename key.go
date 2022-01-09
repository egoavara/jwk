package jwk

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/url"
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
func (key *BaseKey) intoBaseKey() *BaseKey {
	return key
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
	// TODO : Fatal error?
	extra := key.extra
	extra["n"] = base64.RawURLEncoding.EncodeToString(key.Key.N.Bytes())
	extra["e"] = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.Key.E)).Bytes())
	extra["d"] = base64.RawURLEncoding.EncodeToString(key.Key.D.Bytes())
	extra["p"] = base64.RawURLEncoding.EncodeToString(key.Key.Primes[0].Bytes())
	extra["q"] = base64.RawURLEncoding.EncodeToString(key.Key.Primes[1].Bytes())
	extra["dp"] = base64.RawURLEncoding.EncodeToString(key.Key.Precomputed.Dp.Bytes())
	extra["dq"] = base64.RawURLEncoding.EncodeToString(key.Key.Precomputed.Dq.Bytes())
	extra["qi"] = base64.RawURLEncoding.EncodeToString(key.Key.Precomputed.Qinv.Bytes())
	// TODO : oth
	return &UnknownKey{
		BaseKey: BaseKey{
			KeyUse:                 key.Use(),
			KeyOperations:          key.KeyOps(),
			Algorithm:              key.Alg(),
			KeyID:                  key.Kid(),
			X509URL:                key.X5u(),
			X509CertChain:          key.X5c(),
			X509CertThumbprint:     key.X5t(),
			X509CertThumbprintS256: key.X5tS256(),
			extra:                  extra,
		},
		KeyType: key.Kty(),
	}
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
	// TODO : Fatal error?
	extra := key.extra
	extra["n"] = base64.RawURLEncoding.EncodeToString(key.Key.N.Bytes())
	extra["e"] = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.Key.E)).Bytes())
	// TODO : oth
	return &UnknownKey{
		BaseKey: BaseKey{
			KeyUse:                 key.Use(),
			KeyOperations:          key.KeyOps(),
			Algorithm:              key.Alg(),
			KeyID:                  key.Kid(),
			X509URL:                key.X5u(),
			X509CertChain:          key.X5c(),
			X509CertThumbprint:     key.X5t(),
			X509CertThumbprintS256: key.X5tS256(),
			extra:                  extra,
		},
		KeyType: key.Kty(),
	}
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
	// TODO : Fatal error?
	extra := key.extra
	extra["crv"] = key.Key.Curve.Params().Name
	extra["x"] = base64.RawURLEncoding.EncodeToString(key.Key.X.Bytes())
	extra["y"] = base64.RawURLEncoding.EncodeToString(key.Key.Y.Bytes())
	extra["d"] = base64.RawURLEncoding.EncodeToString(key.Key.D.Bytes())
	// TODO : oth
	return &UnknownKey{
		BaseKey: BaseKey{
			KeyUse:                 key.Use(),
			KeyOperations:          key.KeyOps(),
			Algorithm:              key.Alg(),
			KeyID:                  key.Kid(),
			X509URL:                key.X5u(),
			X509CertChain:          key.X5c(),
			X509CertThumbprint:     key.X5t(),
			X509CertThumbprintS256: key.X5tS256(),
			extra:                  extra,
		},
		KeyType: key.Kty(),
	}
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
	// TODO : Fatal error?
	extra := key.extra
	extra["crv"] = key.Key.Curve.Params().Name
	extra["x"] = base64.RawURLEncoding.EncodeToString(key.Key.X.Bytes())
	extra["y"] = base64.RawURLEncoding.EncodeToString(key.Key.Y.Bytes())
	// TODO : oth
	return &UnknownKey{
		BaseKey: BaseKey{
			KeyUse:                 key.Use(),
			KeyOperations:          key.KeyOps(),
			Algorithm:              key.Alg(),
			KeyID:                  key.Kid(),
			X509URL:                key.X5u(),
			X509CertChain:          key.X5c(),
			X509CertThumbprint:     key.X5t(),
			X509CertThumbprintS256: key.X5tS256(),
			extra:                  extra,
		},
		KeyType: key.Kty(),
	}
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
	// TODO : Fatal error?
	extra := key.extra
	extra["k"] = base64.RawURLEncoding.EncodeToString(key.Key)
	// TODO : oth
	return &UnknownKey{
		BaseKey: BaseKey{
			KeyUse:                 key.Use(),
			KeyOperations:          key.KeyOps(),
			Algorithm:              key.Alg(),
			KeyID:                  key.Kid(),
			X509URL:                key.X5u(),
			X509CertChain:          key.X5c(),
			X509CertThumbprint:     key.X5t(),
			X509CertThumbprintS256: key.X5tS256(),
			extra:                  extra,
		},
		KeyType: key.Kty(),
	}
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
