package jwk

import (
	"context"
	"crypto/tls"
	"net/http"
	"reflect"
)

// optionals
type (
	OptionalEncodeSet interface {
		WithEncodeSet(ctx context.Context) context.Context
	}
	OptionalEncodeKey interface {
		WithEncodeKey(ctx context.Context) context.Context
	}
	OptionalDecodeSet interface {
		WithDecodeSet(ctx context.Context) context.Context
	}
	OptionalDecodeKey interface {
		WithDecodeKey(ctx context.Context) context.Context
	}
	OptionalFetchSet interface {
		WithFetchSet(ctx context.Context) context.Context
	}
	OptionalFetchKey interface {
		WithFetchKey(ctx context.Context) context.Context
	}
)

// options
type (
	OptionEncodeSet struct {
		DisallowUnknownField bool
	}
	OptionEncodeKey struct {
		DisallowUnknownField bool
	}
	OptionDecodeSet struct {
		DisallowUnknownField bool
	}
	OptionDecodeKey struct {
		// if len(KeyType) > 0, decode fail when `kty` != constraintKeyType
		constraintKeyType        KeyType
		forceUnknownKey          bool
		AllowUnknownField        bool
		DisallowUnknownAlgorithm bool
		DisallowUnknownUse       bool
		DisallowUnknownOp        bool
		DisallowDuplicatedOps    bool
		DisallowBothUseAndOps    bool
		IgnorePrecomputed        bool
		IgnoreValidate           bool
		// For RSA Private Key, when this true, it ignore JWK define `dp`, `dq` and `qi` and precomputed values.
		// Recalculate bool
		// If this Value is true, Decoder don't execute key validation
		// If you can trust key is safe set it true
		// NoValidate bool
		// If you want to select a specific key included in a set, use that handler.
		// The handler uses the first value that returns true as the Key.
		// That handler will check the key without kid last and iterate through the lexicographical order.
		// If there is the same kid, it is checked in the order of EC, RSA, and oct using kty.
		// If this value is set, the input of DecodeKey must be in Set format.
		Selector func(Key) bool
		HandleID func(*string) *string
	}
	OptionFetch struct {
		Client *http.Client
	}
)

// withs
type (
	setupDecodeKey struct{ deck func(*OptionDecodeKey) }
	withContext    struct{ context context.Context }
	withHTTPClient struct{ clt *http.Client }
	withSelector   struct{ selector func(Key) bool }
	withHandleID   struct{ handleID func(*string) *string }
)

// utility function for context
func getContextValue(ctx context.Context, ctxtype interface{}, orInsert bool) context.Context {
	reflectCTXType := reflect.TypeOf(ctxtype)
	switch ctxv := ctxtype.(type) {
	case **OptionEncodeSet:
		if v := ctx.Value(reflectCTXType); v != nil {
			*ctxv = v.(*OptionEncodeSet)
			return ctx
		}
		*ctxv = new(OptionEncodeSet)
		if orInsert {
			ctx = context.WithValue(ctx, reflectCTXType, *ctxv)
		}
	case **OptionEncodeKey:
		if v := ctx.Value(reflectCTXType); v != nil {
			*ctxv = v.(*OptionEncodeKey)
			return ctx
		}
		*ctxv = new(OptionEncodeKey)
		if orInsert {
			ctx = context.WithValue(ctx, reflectCTXType, *ctxv)
		}
	case **OptionDecodeSet:
		if v := ctx.Value(reflectCTXType); v != nil {
			*ctxv = v.(*OptionDecodeSet)
			return ctx
		}
		*ctxv = new(OptionDecodeSet)
		if orInsert {
			ctx = context.WithValue(ctx, reflectCTXType, *ctxv)
		}
	case **OptionDecodeKey:
		if v := ctx.Value(reflectCTXType); v != nil {
			*ctxv = v.(*OptionDecodeKey)
			return ctx
		}
		*ctxv = new(OptionDecodeKey)
		if orInsert {
			ctx = context.WithValue(ctx, reflectCTXType, *ctxv)
		}
	case **OptionFetch:
		if v := ctx.Value(reflectCTXType); v != nil {
			*ctxv = v.(*OptionFetch)
			return ctx
		}
		*ctxv = &OptionFetch{
			Client: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						// InsecureSkipVerify:          true,
					},
				},
			},
		}
		if orInsert {
			ctx = context.WithValue(ctx, reflectCTXType, *ctxv)
		}
	default:
		panic("unreachable")
	}
	return ctx
}

//

// for any
func WithContext(overide context.Context) *withContext {
	return &withContext{
		context: overide,
	}
}
func (w *withContext) WithEncodeSet(ctx context.Context) context.Context {
	return w.context
}
func (w *withContext) WithEncodeKey(ctx context.Context) context.Context {
	return w.context
}
func (w *withContext) WithDecodeSet(ctx context.Context) context.Context {
	return w.context
}
func (w *withContext) WithDecodeKey(ctx context.Context) context.Context {
	return w.context
}
func (w *withContext) WithFetchSet(ctx context.Context) context.Context {
	return w.context
}
func (w *withContext) WithFetchKey(ctx context.Context) context.Context {
	return w.context
}

// for
//     `OptionalFetchSet`,
//     `OptionalFetchKey`
func WithHTTPClient(hclt *http.Client) *withHTTPClient {
	return &withHTTPClient{
		clt: hclt,
	}
}
func (w *withHTTPClient) WithFetchSet(ctx context.Context) context.Context {
	var ifset *OptionFetch
	ctx = getContextValue(ctx, &ifset, true)
	ifset.Client = w.clt
	return ctx
}
func (w *withHTTPClient) WithFetchKey(ctx context.Context) context.Context {
	var ifkey *OptionFetch
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.Client = w.clt
	return ctx
}

// for
//     `OptionalFetchKey`
//     `OptionalDecodeKey`
func WithSelector(selector func(Key) bool) *withSelector {
	return &withSelector{
		selector: selector,
	}
}

func (w *withSelector) WithFetchKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.Selector = w.selector
	return ctx
}

func (w *withSelector) WithDecodeKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.Selector = w.selector
	return ctx
}

// // for
// //     `OptionalFetchSet`
// //     `OptionalFetchKey`
// //     `OptionalDecodeSet`
// //     `OptionalDecodeKey`
// func WithLevel(allowUnknown bool) *withAllowUnknown {
// 	return &withAllowUnknown{
// 		allowUnknown: allowUnknown,
// 	}
// }
// func (w *withAllowUnknown) WithFetchSet(ctx context.Context) context.Context {
// 	var ifkey *OptionDecodeKey
// 	ctx = getContextValue(ctx, &ifkey, true)
// 	ifkey.AllowUnknown = w.allowUnknown
// 	return ctx
// }
// func (w *withAllowUnknown) WithDecodeSet(ctx context.Context) context.Context {
// 	var ifkey *OptionDecodeKey
// 	ctx = getContextValue(ctx, &ifkey, true)
// 	ifkey.AllowUnknown = w.allowUnknown
// 	return ctx
// }
// func (w *withAllowUnknown) WithFetchKey(ctx context.Context) context.Context {
// 	var ifkey *OptionDecodeKey
// 	ctx = getContextValue(ctx, &ifkey, true)
// 	ifkey.AllowUnknown = w.allowUnknown
// 	return ctx
// }
// func (w *withAllowUnknown) WithDecodeKey(ctx context.Context) context.Context {
// 	var ifkey *OptionDecodeKey
// 	ctx = getContextValue(ctx, &ifkey, true)
// 	ifkey.AllowUnknown = w.allowUnknown
// 	return ctx
// }

// for
//     `OptionalFetchSet`
//     `OptionalFetchKey`
//     `OptionalDecodeSet`
//     `OptionalDecodeKey`
func WithHandleID(handleID func(s *string) *string) *withHandleID {
	return &withHandleID{
		handleID: handleID,
	}
}

func (w *withHandleID) WithFetchSet(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.HandleID = w.handleID
	return ctx
}
func (w *withHandleID) WithDecodeSet(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.HandleID = w.handleID
	return ctx
}
func (w *withHandleID) WithFetchKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.HandleID = w.handleID
	return ctx
}
func (w *withHandleID) WithDecodeKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.HandleID = w.handleID
	return ctx
}

func SetupDecodeKey(fn func(*OptionDecodeKey)) *setupDecodeKey {
	return &setupDecodeKey{
		deck: fn,
	}
}

func (w *setupDecodeKey) WithFetchSet(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	w.deck(ifkey)
	return ctx
}
func (w *setupDecodeKey) WithDecodeSet(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	w.deck(ifkey)
	return ctx
}
func (w *setupDecodeKey) WithFetchKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	w.deck(ifkey)
	return ctx
}
func (w *setupDecodeKey) WithDecodeKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	w.deck(ifkey)
	return ctx
}
