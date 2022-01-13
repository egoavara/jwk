package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
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

func MustDecodeKey(reader io.Reader, options ...OptionalDecodeKey) Key {
	key, err := DecodeKey(reader, options...)
	if err != nil {
		panic(err)
	}
	return key
}

func DecodeKeyBy(ctx context.Context, reader io.Reader) (Key, error) {
	if reader == nil {
		return nil, makeErrors(ErrNil, fmt.Errorf("reader is not nilable"))
	}
	select {
	case <-ctx.Done():
		return nil, ErrContextDone
	default:
	}
	var option *OptionDecodeKey
	MustGetOptionFromContext(ctx, &option, false)
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
		return nil, ErrNoSelectedKey
	} else {

		var data map[string]interface{}
		if err := json.NewDecoder(reader).Decode(&data); err != nil {
			return nil, makeErrors(ErrInvalidJSON, err)
		}
		return decodeKeyBy(ctx, option, data)
	}
}

func decodeKeyBy(ctx context.Context, option *OptionDecodeKey, data map[string]interface{}) (Key, error) {

	var result Key
	var bkey BaseKey
	// kty
	skty, ktyerr := utilConsumeStr(data, "kty")
	kty := KeyType(skty)
	if len(option.constraintKeyType) > 0 && option.constraintKeyType != kty {
		return nil, makeErrors(ErrRequirement, FieldError("kty"), ErrNotExpectedKty, fmt.Errorf("expected kty='%s' but got kty='%s'", option.constraintKeyType, kty))
	}

	bkey.extra = make(map[string]interface{})
	if err := decodeBaseKey(&bkey, option, data); err != nil {
		return nil, err
	}

	switch {
	case ktyerr != nil:
		return nil, makeErrors(ErrRequirement, FieldError("kty"), ktyerr)
	case kty == KeyTypeOctet:
		tmp := new(SymetricKey)
		result = tmp
		tmp.BaseKey = bkey
		if err := decodeSymetricKey(&tmp.Key, option, data); err != nil {
			return nil, err
		}
	case kty == KeyTypeEC:
		if _, ok := data["d"]; ok {
			tmp := new(ECPrivateKey)
			result = tmp
			tmp.Key = new(ecdsa.PrivateKey)
			tmp.BaseKey = bkey
			if err := decodeECPriKey(tmp.Key, option, data); err != nil {
				return nil, err
			}
		} else {
			tmp := new(ECPublicKey)
			result = tmp
			tmp.Key = new(ecdsa.PublicKey)
			tmp.BaseKey = bkey
			if err := decodeECPubKey(tmp.Key, option, data); err != nil {
				return nil, err
			}
		}
	case kty == KeyTypeRSA:
		if _, ok := data["d"]; ok {
			tmp := new(RSAPrivateKey)
			result = tmp
			tmp.Key = new(rsa.PrivateKey)
			tmp.BaseKey = bkey
			if err := decodeRSAPriKey(tmp.Key, option, data); err != nil {
				return nil, err
			}
		} else {
			tmp := new(RSAPublicKey)
			result = tmp
			tmp.Key = new(rsa.PublicKey)
			tmp.BaseKey = bkey
			if err := decodeRSAPubKey(tmp.Key, option, data); err != nil {
				return nil, err
			}
		}
	default:
		tmp := new(UnknownKey)
		result = tmp
		tmp.KeyType = kty
		tmp.BaseKey = bkey
		decodeUnknownKey(tmp, option, data)
	}
	//
	if option.AllowUnknownField {
		m := result.Extra()
		for k, v := range data {
			m[k] = v
		}
	} else {
		if len(data) > 0 {
			var errs []error
			for k := range data {
				errs = append(errs, FieldError(k))
			}

			return nil, makeErrors(append([]error{ErrRequirement, ErrDisallowUnkwownField}, errs...)...)
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
				return makeErrors(ErrRequirement, FieldError("use"), ErrUnknownKeyUse, fmt.Errorf("%v", suse))
			}
		}
	} else {
		if !errors.Is(useerr, ErrNotExist) {
			return makeErrors(ErrInvalidJSON, FieldError("use"), useerr)
		}
	}
	// key_ops
	sops, opserr := utilConsumeArrStr(data, "key_ops")
	if opserr == nil {
		m := make(map[KeyOp]struct{})
		for i, sop := range sops {
			op := KeyOp(sop)
			if option.DisallowUnknownOp && !op.IsKnown() {
				return makeErrors(ErrRequirement, ErrCauseOption, FieldError("key_ops"), IndexError(i), ErrDisallowUnknownOp, errors.New(sop))
			}
			if option.DisallowDuplicatedOps {
				if _, ok := m[op]; ok {
					return makeErrors(ErrRequirement, ErrCauseOption, FieldError("key_ops"), IndexError(i), ErrDisallowDuplicatedOps, errors.New(sop))
				}
			}
			m[op] = struct{}{}
		}
		bkey.KeyOperations = KeyOps(m)
		if !bkey.KeyOperations.IsValidCombination() {
			return makeErrors(ErrRequirement, FieldError("key_ops"), ErrInvalidCombination)
		}
	} else {
		if !errors.Is(ErrNotExist, opserr) {
			return makeErrors(ErrRequirement, FieldError("key_ops"), opserr)
		}
		bkey.KeyOperations = make(KeyOps)
	}
	if useerr == nil && opserr == nil {
		if option.DisallowBothUseAndOps {
			return makeErrors(ErrRequirement, ErrCauseOption, FieldError("key_ops"), FieldError("use"), ErrDisallowBothUseKeyops)
		} else if !bkey.KeyOperations.Compatible(bkey.KeyUse) {
			return makeErrors(ErrRequirement, FieldError("key_ops"), FieldError("use"), ErrNotCompatible, fmt.Errorf("use=%s, key_ops=%v", bkey.KeyUse, bkey.KeyOperations.AsSlice()))
		}
	}
	// alg
	salg, algerr := utilConsumeStr(data, "alg")
	if algerr == nil {
		bkey.Algorithm = Algorithm(salg)
		if option.DisallowUnknownAlgorithm && !bkey.Algorithm.IsKnown() {
			return makeErrors(ErrRequirement, ErrCauseOption, FieldError("alg"), ErrDisallowUnknownAlgorithm, errors.New(salg))
		}
	} else {
		if !errors.Is(algerr, ErrNotExist) {
			return makeErrors(ErrRequirement, FieldError("alg"), algerr)
		}
	}
	// kid
	skid, kiderr := utilConsumeStr(data, "kid")
	if kiderr == nil {
		bkey.KeyID = skid
	} else {
		if !errors.Is(kiderr, ErrNotExist) {
			return makeErrors(ErrRequirement, FieldError("kid"), kiderr)
		}
	}
	// x5u
	sx5u, x5uerr := utilConsumeURL(data, "x5u")
	if x5uerr == nil {
		bkey.X509URL = sx5u
		// TODO : Validate x5u

	} else {
		if !errors.Is(x5uerr, ErrNotExist) {
			return makeErrors(ErrRequirement, FieldError("x5u"), x5uerr)
		}
	}
	// x5c
	ax5c, x5cerr := utilConsumeArrStr(data, "x5c")
	if x5cerr == nil {
		bkey.X509CertChain = make([]*x509.Certificate, len(ax5c))
		for i, x5cert := range ax5c {
			bx5cert, err := base64.RawStdEncoding.DecodeString(x5cert)
			if err != nil {
				return makeErrors(ErrRequirement, FieldError("x5c"), IndexError(i), ErrInvalidBase64, err)
			}
			cert, err := x509.ParseCertificate(bx5cert)
			if err != nil {
				return makeErrors(ErrRequirement, FieldError("x5c"), IndexError(i), ErrInvalidX509, err)
			}
			bkey.X509CertChain[i] = cert
		}
		// TODO : Validate x5c
	} else {
		if !errors.Is(x5cerr, ErrNotExist) {
			return makeErrors(ErrRequirement, FieldError("x5c"), x5cerr)
		}
	}
	// x5t
	bx5t, x5terr := utilConsumeB64url(data, "x5t")
	if x5terr == nil {
		if sha1.Size != len(bx5t) {
			return makeErrors(ErrRequirement, FieldError("x5t"), ErrSHA1Size, fmt.Errorf("expected length %d, but got %d", sha1.Size, len(bx5t)))
		}
		bkey.X509CertThumbprint = bx5t
		// TODO : Validate x5t
	} else {
		if !errors.Is(x5terr, ErrNotExist) {
			return makeErrors(ErrRequirement, FieldError("x5t"), x5terr)
		}
	}
	// x5t#S256
	bx5ts, x5tserr := utilConsumeB64url(data, "x5t#S256")
	if x5tserr == nil {
		if sha256.Size != len(bx5ts) {
			return makeErrors(ErrRequirement, FieldError("x5t#S256"), ErrSHA256Size, fmt.Errorf("expected length %d, but got %d", sha256.Size, len(bx5ts)))
		}
		bkey.X509CertThumbprintS256 = bx5ts
		// TODO : Validate x5t#S256
	} else {
		if !errors.Is(x5tserr, ErrNotExist) {
			return makeErrors(ErrRequirement, FieldError("x5t#S256"), x5tserr)
		}
	}
	return nil
}

func decodeSymetricKey(key *[]byte, option *OptionDecodeKey, data map[string]interface{}) error {
	if bn, err := utilConsumeB64url(data, "k"); err == nil {
		*key = bn
	} else {
		return makeErrors(ErrRequirement, ErrCauseSymetricKey, FieldError("k"), err)
	}
	return nil
}

func decodeUnknownKey(key *UnknownKey, option *OptionDecodeKey, data map[string]interface{}) {
	for k, v := range data {
		key.extra[k] = v
		defer delete(data, k)
	}
}

// map to rsa public key
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3
func decodeRSAPubKey(key *rsa.PublicKey, option *OptionDecodeKey, data map[string]interface{}) error {
	// public N
	if bn, err := utilConsumeB64url(data, "n"); err == nil {
		key.N = new(big.Int).SetBytes(bn)
	} else {
		return makeErrors(ErrRequirement, ErrCauseRSAPublicKey, FieldError("n"), err)
	}
	// public E
	if be, err := utilConsumeB64url(data, "e"); err == nil {
		key.E = int(new(big.Int).SetBytes(be).Int64())
	} else {
		return makeErrors(ErrRequirement, ErrCauseRSAPublicKey, FieldError("e"), err)
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
		return makeErrors(ErrRequirement, ErrCauseRSAPrivateKey, FieldError("d"), err)
	}
	if bp, err := utilConsumeB64url(data, "p"); err == nil {
		key.Primes = append(key.Primes, new(big.Int).SetBytes(bp))
	} else {
		return makeErrors(ErrRequirement, ErrCauseRSAPrivateKey, FieldError("p"), err)
	}
	if bq, err := utilConsumeB64url(data, "q"); err == nil {
		key.Primes = append(key.Primes, new(big.Int).SetBytes(bq))
	} else {
		return makeErrors(ErrRequirement, ErrCauseRSAPrivateKey, FieldError("q"), err)
	}
	if option.IgnorePrecomputed {
		delete(data, "dp")
		delete(data, "dq")
		delete(data, "qi")
		key.Precompute()
	} else {
		if bdp, err := utilConsumeB64url(data, "dp"); err == nil {
			key.Precomputed.Dp = new(big.Int).SetBytes(bdp)
		} else {
			return makeErrors(ErrRequirement, ErrCauseRSAPrivateKey, FieldError("dp"), err)
		}
		if bdq, err := utilConsumeB64url(data, "dq"); err == nil {
			key.Precomputed.Dq = new(big.Int).SetBytes(bdq)
		} else {
			return makeErrors(ErrRequirement, ErrCauseRSAPrivateKey, FieldError("dq"), err)
		}
		if bqi, err := utilConsumeB64url(data, "qi"); err == nil {
			key.Precomputed.Qinv = new(big.Int).SetBytes(bqi)
		} else {
			return makeErrors(ErrRequirement, ErrCauseRSAPrivateKey, FieldError("qi"), err)
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
			return makeErrors(ErrRequirement, ErrCauseRSAPrivateKey, ErrCauseRSAValidate, err)
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
			return makeErrors(ErrRequirement, ErrCauseECPublicKey, FieldError("crv"), ErrCauseUnknown, fmt.Errorf("unknown curve '%s'", curve))
		}
	} else {
		return makeErrors(ErrRequirement, ErrCauseECPublicKey, FieldError("crv"), err)
	}
	expectedLength := (key.Curve.Params().BitSize + 7) / 8
	if x, err := utilConsumeB64url(data, "x"); err == nil {
		if len(x) != expectedLength {
			return makeErrors(ErrRequirement, ErrCauseECPublicKey, FieldError("x"), ErrECInvalidBytesLength, fmt.Errorf("expected length %d, but got %d", expectedLength, len(x)))
		}
		key.X = new(big.Int).SetBytes(x)
	} else {
		return makeErrors(ErrRequirement, ErrCauseECPublicKey, FieldError("x"), err)
	}
	if y, err := utilConsumeB64url(data, "y"); err == nil {
		if len(y) != expectedLength {
			return makeErrors(ErrRequirement, ErrCauseECPublicKey, FieldError("y"), ErrECInvalidBytesLength, fmt.Errorf("expected length %d, but got %d", expectedLength, len(y)))
		}
		key.Y = new(big.Int).SetBytes(y)
	} else {
		return makeErrors(ErrRequirement, ErrCauseECPublicKey, FieldError("y"), err)
	}
	return nil
}

// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2
func decodeECPriKey(key *ecdsa.PrivateKey, option *OptionDecodeKey, data map[string]interface{}) error {
	err := decodeECPubKey(&key.PublicKey, option, data)
	if err != nil {
		replaceErrors(err, ErrCauseECPublicKey, ErrCauseECPrivateKey)
		return err
	}
	expectedLength := (key.Curve.Params().BitSize + 7) / 8
	if d, err := utilConsumeB64url(data, "d"); err == nil {
		if len(d) != expectedLength {
			return makeErrors(ErrRequirement, ErrCauseECPublicKey, FieldError("y"), ErrECInvalidBytesLength, fmt.Errorf("expected length %d, but got %d", expectedLength, len(d)))
		}
		key.D = new(big.Int).SetBytes(d)
	} else {
		return makeErrors(ErrRequirement, ErrCauseECPrivateKey, FieldError("d"), err)
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

func MustDecodeSet(reader io.Reader, options ...OptionalDecodeSet) *Set {
	set, err := DecodeSet(reader, options...)
	if err != nil {
		panic(err)
	}
	return set
}

func DecodeSetBy(ctx context.Context, reader io.Reader) (*Set, error) {
	if reader == nil {
		return nil, makeErrors(ErrNil, fmt.Errorf("reader is not nilable"))
	}
	select {
	case <-ctx.Done():
		return nil, ErrContextDone
	default:
	}
	//
	var option *OptionDecodeSet
	MustGetOptionFromContext(ctx, &option, false)
	var optionk *OptionDecodeKey
	MustGetOptionFromContext(ctx, &optionk, false)
	var data map[string]interface{}
	if err := json.NewDecoder(reader).Decode(&data); err != nil {
		return nil, makeErrors(ErrInvalidJSON, err)
	}
	var result = new(Set)
	if akey, err := utilConsumeArrMap(data, "keys"); err == nil {
		result.Keys = make([]Key, len(akey))
		for i, m := range akey {
			result.Keys[i], err = decodeKeyBy(ctx, optionk, m)
			if err != nil {
				return nil, makeErrors(ErrInnerKey, FieldError("keys"), IndexError(i), err)
			}
		}
	} else {
		return nil, makeErrors(ErrRequirement, FieldError("keys"), err)
	}
	if option.DisallowUnknownField && len(data) > 0 {
		var errs []error
		for k := range data {
			errs = append(errs, FieldError(k))
		}
		return nil, makeErrors(append([]error{ErrRequirement, ErrDisallowUnkwownField}, errs...)...)
	}
	result.Extra = data
	return result, nil
}
