package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
)

func EncodeKey(src Key, dst io.Writer, options ...OptionalEncodeKey) error {
	ctx := context.Background()
	for _, option := range options {
		ctx = option.WithEncodeKey(ctx)
	}
	return EncodeKeyBy(ctx, src, dst)
}

func EncodeKeyBy(ctx context.Context, src Key, dst io.Writer) error {
	if src == nil {
		return makeErrors(ErrNil, fmt.Errorf("src is not nilable"))
	}
	if dst == nil {
		return makeErrors(ErrNil, fmt.Errorf("dst is not nilable"))
	}
	select {
	case <-ctx.Done():
		return ErrContextDone
	default:
	}
	var option *OptionEncodeKey
	MustGetOptionFromContext(ctx, &option, false)
	data := map[string]interface{}{"kty": src.Kty()}
	if src.Use().Exist() {
		data["use"] = src.Use()
	}
	if len(src.KeyOps()) > 0 {
		data["key_ops"] = src.KeyOps().AsSlice()
	}
	if src.Alg().Exist() {
		data["alg"] = src.Alg()
	}
	if len(src.Kid()) > 0 {
		data["kid"] = src.Kid()
	}
	if src.X5u() != nil {
		data["x5u"] = src.X5u().String()
	}
	if len(src.X5c()) > 0 {
		certs := make([]string, len(src.X5c()))
		for i, c := range src.X5c() {
			certs[i] = base64.RawStdEncoding.EncodeToString(c.Raw)
		}
		data["x5c"] = certs
	}
	if len(src.X5t()) > 0 {
		data["x5t"] = base64.RawURLEncoding.EncodeToString(src.X5t())
	}
	if len(src.X5tS256()) > 0 {
		data["x5t#S256"] = base64.RawURLEncoding.EncodeToString(src.X5tS256())
	}

	switch gokey := src.(type) {
	case *RSAPrivateKey:
		if err := encodePriRSA(data, gokey.Key); err != nil {
			return err
		}
	case *RSAPublicKey:
		encodePubRSA(data, gokey.Key)
	case *ECPrivateKey:
		encodePriEC(data, gokey.Key)
	case *ECPublicKey:
		encodePubEC(data, gokey.Key)
	case *SymetricKey:
		encodeSym(data, gokey.Key)
	case *UnknownKey:
	default:
	}
	if !option.DisallowUnknownField {
		for k, v := range src.Extra() {
			data[k] = v
		}
	}
	if err := json.NewEncoder(dst).Encode(data); err != nil {
		return makeErrors(ErrInvalidJSON, err)
	}
	return nil
}

func encodePriRSA(data map[string]interface{}, prik *rsa.PrivateKey) error {
	encodePubRSA(data, &prik.PublicKey)
	data["d"] = base64.RawURLEncoding.EncodeToString(prik.D.Bytes())
	if len(prik.Primes) >= 2 {
		data["p"] = base64.RawURLEncoding.EncodeToString(prik.Primes[0].Bytes())
		data["q"] = base64.RawURLEncoding.EncodeToString(prik.Primes[1].Bytes())
	} else {
		return makeErrors(ErrParameter, ErrCauseRSAPrivateKey, fmt.Errorf("len(primes) : %d", len(prik.Primes)))
	}
	// make sure precomputed
	// `Precompute` is do nothing when already precomputed, so do it for safety
	prik.Precompute()
	data["dp"] = base64.RawURLEncoding.EncodeToString(prik.Precomputed.Dp.Bytes())
	data["dq"] = base64.RawURLEncoding.EncodeToString(prik.Precomputed.Dq.Bytes())
	data["qi"] = base64.RawURLEncoding.EncodeToString(prik.Precomputed.Qinv.Bytes())
	// TODO : data["oth"] fields
	return nil
}

func encodePubRSA(data map[string]interface{}, pubk *rsa.PublicKey) {
	data["n"] = base64.RawURLEncoding.EncodeToString(pubk.N.Bytes())
	data["e"] = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubk.E)).Bytes())
}

func encodePriEC(data map[string]interface{}, prik *ecdsa.PrivateKey) {
	data["d"] = safeECByte(prik.Params().BitSize, prik.D.Bytes())
	encodePubEC(data, &prik.PublicKey)
}

func encodePubEC(data map[string]interface{}, pubk *ecdsa.PublicKey) {
	data["crv"] = pubk.Curve.Params().Name
	data["x"] = safeECByte(pubk.Params().BitSize, pubk.X.Bytes())
	data["y"] = safeECByte(pubk.Params().BitSize, pubk.Y.Bytes())
}
func safeECByte(bitsize int, bts []byte) string {
	expectedLength := (bitsize + 7) / 8
	if expectedLength != len(bts) {
		buf := make([]byte, expectedLength)
		startAt := expectedLength - len(bts)
		if startAt < 0 {
			startAt = 0
		}
		copy(buf[startAt:], bts)
		bts = buf
	}
	return base64.RawURLEncoding.EncodeToString(bts)
}

func encodeSym(data map[string]interface{}, key []byte) {
	data["k"] = base64.RawURLEncoding.EncodeToString(key)
}

func EncodeSet(src *Set, dst io.Writer, options ...OptionalEncodeSet) error {
	ctx := context.Background()
	for _, option := range options {
		ctx = option.WithEncodeSet(ctx)
	}
	return EncodeSetBy(ctx, src, dst)
}
func EncodeSetBy(ctx context.Context, src *Set, dst io.Writer) error {
	if src == nil {
		return makeErrors(ErrNil, fmt.Errorf("src is not nilable"))
	}
	if dst == nil {
		return makeErrors(ErrNil, fmt.Errorf("dst is not nilable"))
	}
	select {
	case <-ctx.Done():
		return ErrContextDone
	default:
		err := json.NewEncoder(dst).Encode(map[string]interface{}{
			"keys": src.Keys,
		})
		if err != nil {
			return makeErrors(ErrInvalidJSON, err)
		}
		return nil
	}
}
