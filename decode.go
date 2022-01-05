package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
)

func DecodeKey(reader io.Reader, options ...OptionalDecodeKey) (Key, error) {
	ctx := context.Background()
	for _, option := range options {
		ctx = option.WithDecodeKey(ctx)
	}
	return DecodeKeyBy(ctx, reader)
}

func DecodeKeyBy(ctx context.Context, reader io.Reader) (Key, error) {
	if reader == nil {
		return nil, ErrNilSource
	}
	select {
	case <-ctx.Done():
		return nil, ErrAlreadyDone
	default:
	}
	var option *OptionDecodeKey
	getContextValue(ctx, &option, false)
	//
	if option.Selector != nil {
		set, err := DecodeSetBy(ctx, reader)
		if err != nil {
			return nil, err
		}
		tmp := make([]Key, len(set.Keys))
		copy(tmp, set.Keys)
		SortKey(tmp)
		for _, k := range tmp {
			if option.Selector(k) {
				return k, nil
			}
		}
		return nil, ErrNilSource
	} else {

		var data map[string]interface{}
		if err := json.NewDecoder(reader).Decode(&data); err != nil {
			return nil, mkErrors(ErrInvalidJSON, err)
		}
		return decodeKeyBy(ctx, option, data)
	}
}

func decodeKeyBy(ctx context.Context, option *OptionDecodeKey, data map[string]interface{}) (Key, error) {

	var result Key
	var bkey *BaseKey
	// kty
	skty, ktyerr := utilConsumeStr(data, "kty")
	kty := KeyType(skty)
	if len(option.constraintKeyType) > 0 && option.constraintKeyType != kty {
		return nil, mkErrors(ErrRequirement, ErrCauseOption, FieldError("kty"), fmt.Errorf("must be kty=%s but got kty=%s", option.constraintKeyType, kty))
	}
	switch {
	case ktyerr != nil:
		return nil, mkErrors(ErrRequirement, FieldError("kty"), ktyerr)
	case option.forceUnknownKey:
		tmp := new(UnknownKey)
		result = tmp
		bkey = &tmp.BaseKey
		if err := decodeUnknownKey(tmp, option, data); err != nil {
			return nil, err
		}
	case kty == KeyTypeOctet:
		tmp := new(SymetricKey)
		result = tmp
		bkey = &tmp.BaseKey
		if err := decodeSymetricKey(&tmp.Key, option, data); err != nil {
			return nil, err
		}
	case kty == KeyTypeEC:
		if _, ok := data["d"]; ok {
			tmp := new(ECPrivateKey)
			result = tmp
			bkey = &tmp.BaseKey
			tmp.Key = new(ecdsa.PrivateKey)
			if err := decodeECPriKey(tmp.Key, option, data); err != nil {
				return nil, err
			}
		} else {
			tmp := new(ECPublicKey)
			result = tmp
			bkey = &tmp.BaseKey
			tmp.Key = new(ecdsa.PublicKey)
			if err := decodeECPubKey(tmp.Key, option, data); err != nil {
				return nil, err
			}
		}
	case kty == KeyTypeRSA:
		if _, ok := data["d"]; ok {
			tmp := new(RSAPrivateKey)
			result = tmp
			bkey = &tmp.BaseKey
			tmp.Key = new(rsa.PrivateKey)
			if err := decodeRSAPriKey(tmp.Key, option, data); err != nil {
				return nil, err
			}
		} else {
			tmp := new(RSAPublicKey)
			result = tmp
			bkey = &tmp.BaseKey
			tmp.Key = new(rsa.PublicKey)
			if err := decodeRSAPubKey(tmp.Key, option, data); err != nil {
				return nil, err
			}
		}
	default:
		tmp := new(UnknownKey)
		result = tmp
		bkey = &tmp.BaseKey
		if err := decodeUnknownKey(tmp, option, data); err != nil {
			return nil, err
		}
	}
	// use, key_ops, alg, kid, x5u, x5c, x5t, x5t#S256
	if err := decodeBaseKey(bkey, option, data); err != nil {
		return nil, err
	}
	//
	if !option.AllowUnknownField {
		if len(data) > 0 {
			var errs []error
			for k := range data {
				errs = append(errs, FieldError(k))
			}

			return nil, mkErrors(append([]error{ErrRequirement, ErrCauseOption}, errs...)...)
		}
	}
	return result, nil
}

func decodeBaseKey(bkey *BaseKey, option *OptionDecodeKey, data map[string]interface{}) error {
	// use
	suse, useerr := utilConsumeStr(data, "use")
	if useerr == nil {
		bkey.KeyUse = KeyUse(suse)
		if option.DisallowUnknownUse {
			if !bkey.KeyUse.IsKnown() {
				return mkErrors(ErrRequirement, ErrCauseOption, FieldError("use"), fmt.Errorf("not well-known value '%s' for use", suse))
			}
		}
	} else {
		if !errors.Is(ErrNotExist, useerr) {
			return mkErrors(ErrInvalidJSON, FieldError("use"), useerr)
		}
	}
	// key_ops
	sops, opserr := utilConsumeArrStr(data, "key_ops")
	if opserr == nil {
		m := make(map[KeyOp]struct{})
		for i, sop := range sops {
			op := KeyOp(sop)
			if option.DisallowUnknownOp && !op.IsKnown() {
				return mkErrors(ErrRequirement, ErrCauseOption, FieldError("key_ops"), IndexError(i), fmt.Errorf("not well-known value '%s' for op", sop))
			}
			if option.DisallowDuplicatedOps {
				if _, ok := m[op]; ok {
					return mkErrors(ErrRequirement, ErrCauseOption, FieldError("key_ops"), IndexError(i), fmt.Errorf("duplicated op '%s'", sop))
				}
			}
			m[op] = struct{}{}
		}
		bkey.KeyOperations = KeyOps(m)
		if !bkey.KeyOperations.IsValidCombination() {
			return mkErrors(ErrRequirement, FieldError("key_ops"), fmt.Errorf("invalid combination %v", bkey.KeyOperations.AsSlice()))
		}
	} else {
		if !errors.Is(ErrNotExist, opserr) {
			return mkErrors(ErrRequirement, FieldError("key_ops"), opserr)
		}
	}
	if useerr == nil && opserr == nil {
		if option.DisallowBothUseAndOps {
			return mkErrors(ErrRequirement, ErrCauseOption, FieldError("key_ops"), FieldError("use"), fmt.Errorf("disallow both 'use' and 'key_ops'"))
		} else if !bkey.KeyOperations.Compatible(bkey.KeyUse) {
			return mkErrors(ErrRequirement, FieldError("key_ops"), FieldError("use"), fmt.Errorf("not compatible use=%s and key_ops=%v", bkey.KeyUse, bkey.KeyOperations.AsSlice()))
		}
	}
	// alg
	salg, algerr := utilConsumeStr(data, "alg")
	if algerr == nil {
		bkey.Algorithm = Algorithm(salg)
		if option.DisallowUnknownAlgorithm && !bkey.Algorithm.IsKnown() {
			return mkErrors(ErrRequirement, ErrCauseOption, FieldError("alg"), fmt.Errorf("unknown algorithm %s", bkey.Algorithm))
		}
	} else {
		if !errors.Is(ErrNotExist, algerr) {
			return mkErrors(ErrRequirement, FieldError("alg"), algerr)
		}
	}
	// kid
	skid, kiderr := utilConsumeStr(data, "kid")
	if kiderr == nil {
		bkey.KeyID = skid
	} else {
		if !errors.Is(ErrNotExist, kiderr) {
			return mkErrors(ErrRequirement, FieldError("kid"), kiderr)
		}
	}
	// x5u
	sx5u, x5uerr := utilConsumeURL(data, "x5u")
	if x5uerr == nil {
		bkey.X509URL = sx5u
		// TODO : Validate x5u
	} else {
		if !errors.Is(ErrNotExist, x5uerr) {
			return mkErrors(ErrRequirement, FieldError("x5u"), x5uerr)
		}
	}
	// x5c
	ax5c, x5cerr := utilConsumeArrStr(data, "x5c")
	if x5cerr == nil {
		bkey.X509CertChain = make([]*x509.Certificate, len(ax5c))
		for i, x5cert := range ax5c {
			bx5cert, err := base64.RawStdEncoding.DecodeString(x5cert)
			if err != nil {
				return mkErrors(ErrRequirement, FieldError("x5c"), IndexError(i), ErrInvalidBase64Std, err)
			}
			cert, err := x509.ParseCertificate(bx5cert)
			if err != nil {
				return mkErrors(ErrRequirement, FieldError("x5c"), IndexError(i), ErrInvalidX509, err)
			}
			bkey.X509CertChain[i] = cert
		}
		// TODO : Validate x5c
	} else {
		if !errors.Is(ErrNotExist, x5cerr) {
			return mkErrors(ErrRequirement, FieldError("x5c"), x5cerr)
		}
	}
	// x5t
	bx5t, x5terr := utilConsumeB64url(data, "x5t")
	if x5uerr == nil {
		bkey.X509CertThumbprint = bx5t
		// TODO : Validate x5t
	} else {
		if !errors.Is(ErrNotExist, x5terr) {
			return mkErrors(ErrRequirement, FieldError("x5t"), x5terr)
		}
	}
	// x5t#S256
	bx5ts, x5tserr := utilConsumeB64url(data, "x5t#S256")
	if x5uerr == nil {
		bkey.X509CertThumbprintS256 = bx5ts
		// TODO : Validate x5t#S256
	} else {
		if !errors.Is(ErrNotExist, x5tserr) {
			return mkErrors(ErrRequirement, FieldError("x5t#S256"), x5tserr)
		}
	}
	return nil
}

func decodeSymetricKey(key *[]byte, option *OptionDecodeKey, data map[string]interface{}) error {
	if bn, err := utilConsumeB64url(data, "k"); err == nil {
		*key = bn
	} else {
		return mkErrors(ErrRequirement, ErrCauseSymetricKey, FieldError("k"), err)
	}
	return nil
}

func decodeUnknownKey(key *UnknownKey, option *OptionDecodeKey, data map[string]interface{}) error {
	for k, v := range data {
		key.extra[k] = v
		defer delete(data, k)
	}
	return nil
}

// map to rsa public key
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3
func decodeRSAPubKey(key *rsa.PublicKey, option *OptionDecodeKey, data map[string]interface{}) error {
	// public N
	if bn, err := utilConsumeB64url(data, "n"); err == nil {
		key.N = new(big.Int).SetBytes(bn)
	} else {
		return mkErrors(ErrRequirement, ErrCauseRSAPublicKey, FieldError("n"), err)
	}
	// public E
	if be, err := utilConsumeB64url(data, "e"); err == nil {
		key.E = int(new(big.Int).SetBytes(be).Int64())
	} else {
		return mkErrors(ErrRequirement, ErrCauseRSAPublicKey, FieldError("e"), err)
	}
	return nil
}

// decodeRSAPriKey must after decodeRSAPubKey
// it return nil if it is not private key
// for example, when rsa public key, it return nil, nil
// `recalculate` true when you need to do `rsa.PrivateKey.Precompute` manualy, but it automaticaly set this value to true when there is no precomputed values
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3
func decodeRSAPriKey(key *rsa.PrivateKey, option *OptionDecodeKey, data map[string]interface{}) error {
	// public N, E
	if err := decodeRSAPubKey(&key.PublicKey, option, data); err != nil {
		replaceErrors(err, ErrCauseRSAPublicKey, ErrCauseRSAPrivateKey)
		return err
	}
	// private D
	if bd, err := utilConsumeB64url(data, "d"); err == nil {
		key.D = new(big.Int).SetBytes(bd)
	} else {
		return mkErrors(ErrRequirement, ErrCauseRSAPrivateKey, FieldError("d"), err)
	}
	if bp, err := utilConsumeB64url(data, "p"); err == nil {
		key.Primes = append(key.Primes, new(big.Int).SetBytes(bp))
	} else {
		return mkErrors(ErrRequirement, ErrCauseRSAPrivateKey, FieldError("p"), err)
	}
	if bq, err := utilConsumeB64url(data, "q"); err == nil {
		key.Primes = append(key.Primes, new(big.Int).SetBytes(bq))
	} else {
		return mkErrors(ErrRequirement, ErrCauseRSAPrivateKey, FieldError("q"), err)
	}
	if option.IgnorePrecomputed {
		key.Precompute()
	} else {
		if bdp, err := utilConsumeB64url(data, "dp"); err == nil {
			key.Precomputed.Dp = new(big.Int).SetBytes(bdp)
		} else {
			return mkErrors(ErrRequirement, ErrCauseRSAPrivateKey, FieldError("dp"), err)
		}
		if bdq, err := utilConsumeB64url(data, "dq"); err == nil {
			key.Precomputed.Dq = new(big.Int).SetBytes(bdq)
		} else {
			return mkErrors(ErrRequirement, ErrCauseRSAPrivateKey, FieldError("dq"), err)
		}
		if bqi, err := utilConsumeB64url(data, "qi"); err == nil {
			key.Precomputed.Qinv = new(big.Int).SetBytes(bqi)
		} else {
			return mkErrors(ErrRequirement, ErrCauseRSAPrivateKey, FieldError("qi"), err)
		}
	}
	// TODO : data["oth"]
	// var oth []*big.Int
	// if both, err := utilConsumeArrMap(data, "oth"); err == nil {
	// 	oth = make([]*big.Int, len(both))
	// 	for i, v := range both {
	// 		oth[i]
	// 	}
	// } else {
	// 	if errors.Is(err, errKeyNotExist) {
	// 		// this value is optional.
	// 	} else if errors.Is(err, errInvalidType) {
	// 		return nil, errorCause(ErrKeyPubRSAFailed, "'oth' must be string")
	// 	} else {
	// 		return nil, &Error{Cause: ErrKeyPubRSAFailed, Detail: err}
	// 	}
	// }
	if !option.IgnoreValidate {
		if err := key.Validate(); err != nil {
			return mkErrors(ErrRequirement, ErrCauseRSAPrivateKey, err)
		}
	}
	return nil
}

// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2
func decodeECPubKey(key *ecdsa.PublicKey, option *OptionDecodeKey, data map[string]interface{}) error {
	if curve, err := utilConsumeStr(data, "crv"); err == nil {
		switch curve {
		case "P-256":
			key.Curve = elliptic.P256()
		case "P-384":
			key.Curve = elliptic.P384()
		case "P-521":
			key.Curve = elliptic.P521()
		default:
			return mkErrors(ErrRequirement, ErrCauseECPublicKey, FieldError("crv"), fmt.Errorf("unknown curve '%s'", curve))
		}
	} else {
		return mkErrors(ErrRequirement, ErrCauseECPublicKey, FieldError("crv"), err)
	}
	if x, err := utilConsumeB64url(data, "x"); err == nil {
		key.X = new(big.Int).SetBytes(x)
	} else {
		return mkErrors(ErrRequirement, ErrCauseECPublicKey, FieldError("x"), err)
	}
	if y, err := utilConsumeB64url(data, "y"); err == nil {
		key.Y = new(big.Int).SetBytes(y)
	} else {
		return mkErrors(ErrRequirement, ErrCauseECPublicKey, FieldError("y"), err)
	}
	return nil
}

// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2
func decodeECPriKey(key *ecdsa.PrivateKey, option *OptionDecodeKey, data map[string]interface{}) error {
	if err := decodeECPubKey(&key.PublicKey, option, data); err != nil {
		replaceErrors(err, ErrCauseECPublicKey, ErrCauseECPrivateKey)
		return err
	}
	if d, err := utilConsumeB64url(data, "d"); err == nil {
		key.D = new(big.Int).SetBytes(d)
	} else {
		return mkErrors(ErrRequirement, ErrCauseECPublicKey, FieldError("d"), err)
	}
	return nil
}

func DecodeSet(reader io.Reader, options ...OptionalDecodeSet) (*Set, error) {
	ctx := context.Background()
	for _, option := range options {
		ctx = option.WithDecodeSet(ctx)
	}
	return DecodeSetBy(ctx, reader)
}

func DecodeSetBy(ctx context.Context, reader io.Reader) (*Set, error) {
	select {
	case <-ctx.Done():
		return nil, ErrAlreadyDone
	default:
	}
	//
	var option *OptionDecodeSet
	getContextValue(ctx, &option, false)
	var optionk *OptionDecodeKey
	getContextValue(ctx, &optionk, false)
	var data map[string]interface{}
	if err := json.NewDecoder(reader).Decode(&data); err != nil {
		return nil, mkErrors(ErrInvalidJSON, err)
	}
	var result = new(Set)
	var err error
	if ikeys, ok := data["keys"]; ok {
		delete(data, "keys")
		if akeys, ok := ikeys.([]interface{}); ok {
			result.Keys = make([]Key, len(akeys))
			for i, v := range akeys {
				if m, ok := v.(map[string]interface{}); ok {
					result.Keys[i], err = decodeKeyBy(ctx, optionk, m)
					if err != nil {
						return nil, mkErrors(ErrRequirement, ErrInnerKey, FieldError("keys"), IndexError(i), err)
					}
				} else {
					return nil, mkErrors(ErrRequirement, ErrInnerKey, FieldError("keys"), IndexError(i), ErrInvalidObject)
				}
			}
		} else {
			return nil, mkErrors(ErrRequirement, FieldError("keys"), ErrInvalidArrayObject)
		}
	} else {
		return nil, mkErrors(ErrRequirement, FieldError("keys"), ErrNotExist)
	}
	if option.DisallowUnknownField && len(data) > 0 {
		var errs []error
		for k := range data {
			errs = append(errs, FieldError(k))
		}
		return nil, mkErrors(append([]error{ErrRequirement, ErrCauseOption}, errs...)...)
	}
	result.Extra = data
	return result, nil
}
