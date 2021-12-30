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
	"io"
	"math/big"
	"strings"
)

type (
	innerJWKSet struct {
		Keys []json.RawMessage `json:"keys"`
	}
	innerJWKSetEachKey struct {
		Index int
		Value *Key
	}
	innerJWKKeyLeft struct {
		Value *Key
		Map   map[string]interface{}
	}
)

func DecodeKey(reader io.Reader, options ...OptionalDecodeKey) (*Key, error) {
	ctx := context.Background()
	for _, option := range options {
		ctx = option.WithDecodeKey(ctx)
	}
	return DecodeKeyBy(ctx, reader)
}

func DecodeKeyBy(ctx context.Context, reader io.Reader) (*Key, error) {
	var option *OptionDecodeKey
	getContextValue(ctx, &option, false)
	doneResult := make(chan interface{}, 1)
	// Step 1 : JSON Decode
	go func() {
		var data map[string]interface{}
		err := json.NewDecoder(reader).Decode(&data)
		select {
		case <-ctx.Done():
			close(doneResult)
		default:
			if err != nil {
				doneResult <- &ErrorDetail{
					Cause:  ErrJSON,
					Detail: err,
				}
			} else {
				doneResult <- data
			}
		}

	}()
	//
	for v := range doneResult {
		switch v := v.(type) {
		// Step 2 : decoded json to jwk key
		case map[string]interface{}:
			go func() {
				var key = new(Key)
				// kty
				if kty, err := utilConsumeStr(v, "kty"); err == nil {
					key.KeyType = KeyType(kty)
				} else {
					doneResult <- ErrKeyNoRequired
					return
				}
				// use
				if use, err := utilConsumeStr(v, "use"); err == nil {
					key.KeyUse = KeyUse(use)
				} else {
					if !errors.Is(err, errKeyNotExist) {
						doneResult <- errorCauseFieldFrom(ErrKeyParse, "use", err)
						return
					}
				}
				// key_ops
				if keyops, err := utilConsumeArrStr(v, "key_ops"); err == nil {
					key.KeyOperations = NewKeyOpsFromStr(keyops...)
				} else {
					if !errors.Is(err, errKeyNotExist) {
						doneResult <- errorCauseFieldFrom(ErrKeyParse, "key_ops", err)
						return
					}
				}
				// alg
				if alg, err := utilConsumeStr(v, "alg"); err == nil {
					key.Algorithm = Algorithm(alg)
				} else {
					if !errors.Is(err, errKeyNotExist) {
						doneResult <- errorCauseFieldFrom(ErrKeyParse, "alg", err)
						return
					}
				}
				// kid
				if kid, err := utilConsumeStr(v, "kid"); err == nil {
					key.KeyID = kid
				} else {
					if !errors.Is(err, errKeyNotExist) {
						doneResult <- errorCauseFieldFrom(ErrKeyParse, "kid", err)
						return
					}
				}
				if len(option.AssignID) > 0 {
					key.KeyID = option.AssignID
				}
				// x5u
				if x5u, err := utilConsumeURL(v, "x5u"); err == nil {
					key.X509URL = x5u
				} else {
					if !errors.Is(err, errKeyNotExist) {
						doneResult <- errorCauseFieldFrom(ErrKeyParse, "x5u", err)
						return
					}
				}
				// x5c
				if x5c, err := utilConsumeArrStr(v, "x5c"); err == nil {
					cert := make([]*x509.Certificate, len(x5c))
					for i, c := range x5c {
						bts, err := base64.StdEncoding.DecodeString(c)
						if err != nil {
							doneResult <- errorCauseFieldFrom(ErrX509Certificate, "x5c", err)
							return
						}
						x509cert, err := x509.ParseCertificate(bts)
						if err != nil {
							doneResult <- errorCauseFieldFrom(ErrX509Certificate, "x5c", err)
							return
						}
						cert[i] = x509cert
					}
					key.X509CertChain = cert
				} else {
					if !errors.Is(err, errKeyNotExist) {
						doneResult <- errorCauseFieldFrom(ErrKeyParse, "x5c", err)
						return
					}
				}
				// x5t
				if x5t, err := utilConsumeB64url(v, "x5t"); err == nil {
					key.X509CertThumbprint = x5t
				} else {
					if !errors.Is(err, errKeyNotExist) {
						doneResult <- errorCauseFieldFrom(ErrKeyParse, "x5t", err)
						return
					}
				}
				// x5t#s256
				if x5ts256, err := utilConsumeB64url(v, "x5t#s256"); err == nil {
					key.X509CertThumbprintS256 = x5ts256
				} else {
					if !errors.Is(err, errKeyNotExist) {
						doneResult <- errorCauseFieldFrom(ErrKeyParse, "x5t#s256", err)
						return
					}
				}
				// parse jwk to golang stdlib struct
				switch key.KeyType {
				case KeyTypeRSA:
					pubk, err := decodeRSAPubKey(v)
					if err != nil {
						doneResult <- err
						return
					}
					prik, err := decodeRSAPriKey(v, pubk, option.Recalculate, option.NoValidate)
					if err != nil {
						doneResult <- err
						return
					}
					if prik == nil {
						key.Raw = pubk
					} else {
						key.Raw = prik
					}
				case KeyTypeEC:
					pubk, err := decodeECPubKey(v)
					if err != nil {
						doneResult <- err
						return
					}
					prik, err := decodeECPriKey(v, pubk)
					if err != nil {
						doneResult <- err
						return
					}
					if prik == nil {
						key.Raw = pubk
					} else {
						key.Raw = prik
					}
				case KeyTypeOctet:
					// TODO : EC
					panic("unimplemented")
				}
				// jobs done
				select {
				case <-ctx.Done():
					close(doneResult)
				default:
					doneResult <- &innerJWKKeyLeft{
						Value: key,
						Map:   v,
					}
				}
			}()
		// Step 3 : Check Strict Mode
		case *innerJWKKeyLeft:
			if option.Strict && len(v.Map) > 0 {
				builder := new(strings.Builder)
				builder.WriteString("[")
				for k := range v.Map {
					builder.WriteString("\"")
					builder.WriteString(k)
					builder.WriteString("\", ")
				}
				builder.WriteString("]")

				return nil, errorCause(ErrKeyUnknownField, builder.String())
			}
			return v.Value, nil
		case error:
			return nil, v
		}
	}
	return nil, ErrContextDone
}

// map to rsa public key
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3
func decodeRSAPubKey(data map[string]interface{}) (*rsa.PublicKey, error) {
	var n, e *big.Int
	// public
	if bn, err := utilConsumeB64url(data, "n"); err == nil {
		n = new(big.Int).SetBytes(bn)
	} else {
		if errors.Is(err, errKeyNotExist) {
			return nil, errorCauseField(ErrKeyPubRSAFailed, "n", "not exist")
		} else if errors.Is(err, errInvalidType) {
			return nil, errorCauseField(ErrKeyPubRSAFailed, "n", "must be string")
		} else {
			return nil, errorCauseFieldFrom(ErrKeyPubRSAFailed, "n", err)
		}
	}
	if be, err := utilConsumeB64url(data, "e"); err == nil {
		e = new(big.Int).SetBytes(be)
	} else {
		if errors.Is(err, errKeyNotExist) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'e' not exist")
		} else if errors.Is(err, errInvalidType) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'e' must be string")
		} else {
			return nil, &ErrorDetail{Cause: ErrKeyPubRSAFailed, Detail: err}
		}
	}
	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// decodeRSAPriKey must after decodeRSAPubKey
// it return nil if it is not private key
// for example, when rsa public key, it return nil, nil
// `recalculate` true when you need to do `rsa.PrivateKey.Precompute` manualy, but it automaticaly set this value to true when there is no precomputed values
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3
func decodeRSAPriKey(data map[string]interface{}, pubk *rsa.PublicKey, recalculate bool, noValidate bool) (*rsa.PrivateKey, error) {
	var d, p, q, dp, dq, qi *big.Int

	if bd, err := utilConsumeB64url(data, "d"); err == nil {
		d = new(big.Int).SetBytes(bd)
	} else {
		if errors.Is(err, errKeyNotExist) {
			// D must exist when this `data` is RSA private key
			return nil, nil
		} else if errors.Is(err, errInvalidType) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'d' must be string")
		} else {
			return nil, &ErrorDetail{Cause: ErrKeyPubRSAFailed, Detail: err}
		}
	}
	if bp, err := utilConsumeB64url(data, "p"); err == nil {
		p = new(big.Int).SetBytes(bp)
	} else {
		if errors.Is(err, errKeyNotExist) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'p' not exist")
		} else if errors.Is(err, errInvalidType) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'p' must be string")
		} else {
			return nil, &ErrorDetail{Cause: ErrKeyPubRSAFailed, Detail: err}
		}
	}
	if bq, err := utilConsumeB64url(data, "q"); err == nil {
		q = new(big.Int).SetBytes(bq)
	} else {
		if errors.Is(err, errKeyNotExist) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'q' not exist")
		} else if errors.Is(err, errInvalidType) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'q' must be string")
		} else {
			return nil, &ErrorDetail{Cause: ErrKeyPubRSAFailed, Detail: err}
		}
	}
	if bdp, err := utilConsumeB64url(data, "dp"); err == nil {
		dp = new(big.Int).SetBytes(bdp)
	} else {
		if errors.Is(err, errKeyNotExist) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'dp' not exist")
		} else if errors.Is(err, errInvalidType) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'dp' must be string")
		} else {
			return nil, &ErrorDetail{Cause: ErrKeyPubRSAFailed, Detail: err}
		}
	}
	if bdq, err := utilConsumeB64url(data, "dq"); err == nil {
		dq = new(big.Int).SetBytes(bdq)
	} else {
		if errors.Is(err, errKeyNotExist) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'dq' not exist")
		} else if errors.Is(err, errInvalidType) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'dq' must be string")
		} else {
			return nil, &ErrorDetail{Cause: ErrKeyPubRSAFailed, Detail: err}
		}
	}
	if bqi, err := utilConsumeB64url(data, "qi"); err == nil {
		qi = new(big.Int).SetBytes(bqi)
	} else {
		if errors.Is(err, errKeyNotExist) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'qi' not exist")
		} else if errors.Is(err, errInvalidType) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'qi' must be string")
		} else {
			return nil, &ErrorDetail{Cause: ErrKeyPubRSAFailed, Detail: err}
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
	prik := &rsa.PrivateKey{
		PublicKey: *pubk,
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	if recalculate {
		prik.Precompute()
	} else {
		prik.Precomputed.Dp = dp
		prik.Precomputed.Dq = dq
		prik.Precomputed.Qinv = qi
	}
	if !noValidate {
		err := prik.Validate()
		if err != nil {
			return nil, &ErrorDetail{
				Cause:  ErrKeyPriRSAFailed,
				Detail: err,
			}
		}
	}
	return prik, nil
}

// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2
func decodeECPubKey(data map[string]interface{}) (*ecdsa.PublicKey, error) {
	var pubk = new(ecdsa.PublicKey)
	if curve, err := utilConsumeStr(data, "crv"); err == nil {
		switch curve {
		case "P-256":
			pubk.Curve = elliptic.P256()
		case "P-384":
			pubk.Curve = elliptic.P384()
		case "P-521":
			pubk.Curve = elliptic.P521()
		default:
			return nil, errorCause(ErrKeyPubRSAFailed, "unknown curve : '%s'", curve)
		}
	} else {
		if errors.Is(err, errKeyNotExist) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'crv' not exist")
		} else if errors.Is(err, errInvalidType) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'crv' must be string")
		} else {
			panic("unreachable")
		}
	}
	if x, err := utilConsumeB64url(data, "x"); err == nil {
		pubk.X = new(big.Int).SetBytes(x)
	} else {
		if errors.Is(err, errKeyNotExist) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'x' not exist")
		} else if errors.Is(err, errInvalidType) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'x' must be string")
		} else {
			return nil, errorCause(ErrKeyPubRSAFailed, "'x' b64 failed : %e", err)
		}
	}
	if y, err := utilConsumeB64url(data, "y"); err == nil {
		pubk.Y = new(big.Int).SetBytes(y)
	} else {
		if errors.Is(err, errKeyNotExist) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'y' not exist")
		} else if errors.Is(err, errInvalidType) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'y' must be string")
		} else {
			return nil, errorCause(ErrKeyPubRSAFailed, "'y' b64 failed : %e", err)
		}
	}
	return pubk, nil
}

// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2
func decodeECPriKey(data map[string]interface{}, pubk *ecdsa.PublicKey) (*ecdsa.PrivateKey, error) {
	var prik = new(ecdsa.PrivateKey)
	prik.PublicKey = *pubk
	if d, err := utilConsumeB64url(data, "d"); err == nil {
		prik.D = new(big.Int).SetBytes(d)
	} else {
		if errors.Is(err, errKeyNotExist) {
			return nil, nil
		} else if errors.Is(err, errInvalidType) {
			return nil, errorCause(ErrKeyPubRSAFailed, "'d' must be string")
		} else {
			return nil, errorCause(ErrKeyPubRSAFailed, "'d' b64 failed : %e", err)
		}
	}
	return prik, nil
}
func DecodeSet(reader io.Reader, options ...OptionalDecodeSet) (*Set, error) {
	ctx := context.Background()
	for _, option := range options {
		ctx = option.WithDecodeSet(ctx)
	}
	return DecodeSetBy(ctx, reader)
}

func DecodeSetBy(ctx context.Context, reader io.Reader) (*Set, error) {
	var option *OptionDecodeSet
	getContextValue(ctx, &option, false)
	doneResult := make(chan interface{}, 1)
	// Step 1 : parse raw text to json unmarshaled struct
	go func() {
		var data innerJWKSet
		dec := json.NewDecoder(reader)
		if option.Strict {
			dec.DisallowUnknownFields()
		}
		err := dec.Decode(&data)
		select {
		case <-ctx.Done():
			close(doneResult)
		default:
			if err != nil {
				doneResult <- &ErrorDetail{
					Cause:  ErrJSON,
					Detail: err,
				}
			} else {
				doneResult <- &data
			}
		}
	}()
	var (
		result = new(Set)
		works  = 0
	)
	for v := range doneResult {
		switch v := v.(type) {
		// Step 2 : make workers for each key
		case *innerJWKSet:
			works = len(v.Keys)
			result.Keys = make([]*Key, len(v.Keys))
			for i, key := range v.Keys {
				go func(i int, key string) {
					res, err := DecodeKeyBy(ctx, strings.NewReader(key))
					select {
					case <-ctx.Done():
						close(doneResult)
					default:
						if err != nil {
							doneResult <- errorCauseAtFrom(ErrSetInnerKey, i, err)
						} else {
							doneResult <- &innerJWKSetEachKey{
								Index: i,
								Value: res,
							}
						}
					}
				}(i, string(key))
			}
		// Step 3 : handle each keys and if job is done, return result of set
		case *innerJWKSetEachKey:
			works -= 1
			result.Keys[v.Index] = v.Value
			if works <= 0 {
				return result, nil
			}
		case error:
			return nil, v
		default:
			panic("unreachable")
		}
	}
	return nil, ErrContextDone
}
