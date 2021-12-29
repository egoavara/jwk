package jwk

import (
	"bytes"
	"context"
	"crypto/x509"
	"net/url"
)

// Set is JWK Set struct
// https://datatracker.ietf.org/doc/html/rfc7517#section-5
type Set struct {
	Keys []*Key // https://datatracker.ietf.org/doc/html/rfc7517#section-5.1
}

// Key is JWK Key struct
// https://datatracker.ietf.org/doc/html/rfc7517#section-4
type Key struct {
	KeyType                KeyType             // https://datatracker.ietf.org/doc/html/rfc7517#section-4.1
	KeyUse                 KeyUse              // https://datatracker.ietf.org/doc/html/rfc7517#section-4.2
	KeyOperations          KeyOps              // https://datatracker.ietf.org/doc/html/rfc7517#section-4.3
	Algorithm              Algorithm           // https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
	KeyID                  string              // https://datatracker.ietf.org/doc/html/rfc7517#section-4.5
	X509URL                *url.URL            // https://datatracker.ietf.org/doc/html/rfc7517#section-4.6
	X509CertChain          []*x509.Certificate // https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
	X509CertThumbprint     []byte              // https://datatracker.ietf.org/doc/html/rfc7517#section-4.8
	X509CertThumbprintS256 []byte              // https://datatracker.ietf.org/doc/html/rfc7517#section-4.9
	// Go language stdlib crypto
	// It can be one of `*rsa.PrivateKey | *rsa.PublicKey | *ecdsa.PrivateKey | *ecdsa.PublicKey`
	Raw interface{}
}

// Return First Key from Set
// If there is no key, it return nil (runtime safe)
func (set *Set) First() *Key {
	if len(set.Keys) > 0 {
		return set.Keys[0]
	}
	return nil
}

// Return Last Key from Set
// If there is no key, it return nil (runtime safe)
func (set *Set) Last() *Key {
	if len(set.Keys) > 0 {
		return set.Keys[len(set.Keys)-1]
	}
	return nil
}

// Return Specified Key from Set
// If there is no key, it return nil (runtime safe)
// In RFC 7517, there is duplicated named key(but different KeyType)
// However, it return first named key sorted by index(order of keys)
// If you need to query, See Set.Gets
func (set *Set) Get(kid string) *Key {
	for _, k := range set.Keys {
		if k.KeyID == kid {
			return k
		}
	}
	return nil
}

// Return Specified Keys from Set
// If there is no key, it return empty slice(nil)
func (set *Set) Gets(kid string) []*Key {
	var result []*Key
	for _, k := range set.Keys {
		if k.KeyID == kid {
			result = append(result, k)
		}
	}
	return result
}

// func (set *Set) Set(key *Key) *Key {
// 	if len(set.Keys) > 0 {
// 		return set.Keys[len(set.Keys)-1]
// 	}
// 	return nil
// }

func (set *Set) UnmarshalJSON(bts []byte) error {
	s, err := DecodeSetBy(context.Background(), bytes.NewReader(bts))
	if err != nil {
		return err
	}
	*set = *s
	return nil
}

func (set *Set) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := EncodeSetBy(context.Background(), set, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (key *Key) UnmarshalJSON(bts []byte) error {
	k, err := DecodeKeyBy(context.Background(), bytes.NewReader(bts))
	if err != nil {
		return err
	}
	*key = *k
	return nil
}

func (key *Key) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := EncodeKeyBy(context.Background(), key, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
