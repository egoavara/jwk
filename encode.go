package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
)

func EncodeKey(src *Key, dst io.Writer, options ...OptionalEncodeKey) error {
	ctx := context.Background()
	for _, option := range options {
		ctx = option.WithEncodeKey(ctx)
	}
	return EncodeKeyBy(ctx, src, dst)
}

func EncodeKeyBy(ctx context.Context, src *Key, dst io.Writer) error {
	select {
	case <-ctx.Done():
		return ErrContextDone
	default:
		data := map[string]interface{}{"kty": src.KeyType}
		if src.KeyUse.Exist() {
			data["use"] = src.KeyUse
		}
		if len(src.KeyOperations) > 0 {
			data["key_ops"] = src.KeyOperations
		}
		if src.Algorithm.Exist() {
			data["alg"] = src.Algorithm
		}
		if src.Algorithm.Exist() {
			data["alg"] = src.Algorithm
		}
		if len(src.KeyID) > 0 {
			data["kid"] = src.KeyID
		}
		if src.X509URL != nil {
			data["x5u"] = src.X509URL.String()
		}
		if len(src.X509CertChain) > 0 {
			certs := make([]string, len(src.X509CertChain))
			for i, c := range src.X509CertChain {
				certs[i] = base64.StdEncoding.EncodeToString(c.Raw)
			}
			data["x5c"] = certs
		}
		if len(src.X509CertThumbprint) > 0 {
			data["x5t"] = base64.StdEncoding.EncodeToString(src.X509CertThumbprint)
		}
		if len(src.X509CertThumbprintS256) > 0 {
			data["x5t#S256"] = base64.URLEncoding.EncodeToString(src.X509CertThumbprintS256)
		}

		switch gokey := src.Raw.(type) {
		case *rsa.PrivateKey:
			if err := encodePriRSA(data, gokey); err != nil {
				return err
			}
		case *rsa.PublicKey:
			encodePubRSA(data, gokey)
		case *ecdsa.PrivateKey:
			encodePriEC(data, gokey)
		case *ecdsa.PublicKey:
			encodePubEC(data, gokey)
		}
		if err := json.NewEncoder(dst).Encode(data); err != nil {
			return &ErrorDetail{
				Cause:  ErrJSON,
				Detail: err,
			}
		}
		return nil
	}
}

func encodePriRSA(data map[string]interface{}, prik *rsa.PrivateKey) error {
	encodePubRSA(data, &prik.PublicKey)
	data["d"] = base64.URLEncoding.EncodeToString(prik.D.Bytes())
	if len(prik.Primes) >= 2 {
		data["p"] = base64.URLEncoding.EncodeToString(prik.Primes[0].Bytes())
		data["q"] = base64.URLEncoding.EncodeToString(prik.Primes[1].Bytes())
	} else {
		return errorCause(ErrKeyPriRSAFailed, "len(primes) : %d", len(prik.Primes))
	}
	// make sure precomputed
	// `Precompute` is do nothing when already precomputed, so it is safe
	prik.Precompute()
	data["dp"] = prik.Precomputed.Dp
	data["dq"] = prik.Precomputed.Dq
	data["qi"] = prik.Precomputed.Qinv
	// TODO : data["oth"] fields
	return nil
}

func encodePubRSA(data map[string]interface{}, pubk *rsa.PublicKey) {
	data["n"] = base64.URLEncoding.EncodeToString(pubk.N.Bytes())
	data["e"] = base64.URLEncoding.EncodeToString(big.NewInt(int64(pubk.E)).Bytes())
}

func encodePriEC(data map[string]interface{}, prik *ecdsa.PrivateKey) {
	data["d"] = base64.URLEncoding.EncodeToString(prik.D.Bytes())
	encodePubEC(data, &prik.PublicKey)
}

func encodePubEC(data map[string]interface{}, pubk *ecdsa.PublicKey) {
	data["crv"] = pubk.Curve.Params().Name
	data["x"] = base64.URLEncoding.EncodeToString(pubk.X.Bytes())
	data["y"] = base64.URLEncoding.EncodeToString(pubk.Y.Bytes())
}

func EncodeSet(src *Set, dst io.Writer, options ...OptionalEncodeSet) error {
	ctx := context.Background()
	for _, option := range options {
		ctx = option.WithEncodeSet(ctx)
	}
	return EncodeSetBy(ctx, src, dst)
}
func EncodeSetBy(ctx context.Context, src *Set, dst io.Writer) error {
	select {
	case <-ctx.Done():
		return ErrContextDone
	default:
		err := json.NewEncoder(dst).Encode(map[string]interface{}{
			"keys": src.Keys,
		})
		if err != nil {
			return &ErrorDetail{
				Cause:  ErrJSON,
				Detail: err,
			}
		}
		return nil
	}
}
