package jwk

import (
	"context"
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
	// Option interface {
	// 	Add(ctx context.Context) context.Context
	// }
)

// options
type (
	OptionEncodeSet struct{}
	OptionEncodeKey struct{}
	OptionDecodeSet struct {
		Strict bool
	}
	OptionDecodeKey struct {
		AssignID    string
		Strict      bool
		Recalculate bool
		NoValidate  bool
		// From JWK Set
		SelectByID string
	}
	OptionFetchSet struct {
		Client *http.Client
	}
	OptionFetchKey struct {
		Client *http.Client
	}
)

// withs
type (
	withContext    struct{ context.Context }
	withHTTPClient struct{ *http.Client }
	withSelectByID struct{ kid string }
	withStrict     struct{ strict bool }
	withRecompute  struct{ recompute bool }
)

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
	case **OptionFetchSet:
		if v := ctx.Value(reflectCTXType); v != nil {
			*ctxv = v.(*OptionFetchSet)
			return ctx
		}
		*ctxv = &OptionFetchSet{
			Client: http.DefaultClient,
		}
		if orInsert {
			ctx = context.WithValue(ctx, reflectCTXType, *ctxv)
		}
	case **OptionFetchKey:
		if v := ctx.Value(reflectCTXType); v != nil {
			*ctxv = v.(*OptionFetchKey)
			return ctx
		}
		*ctxv = &OptionFetchKey{
			Client: http.DefaultClient,
		}
		if orInsert {
			ctx = context.WithValue(ctx, reflectCTXType, *ctxv)
		}
	default:
		panic("unreachable")
	}
	return ctx
}

// for any
func WithContext(overide context.Context) *withContext {
	return &withContext{
		Context: overide,
	}
}
func (w *withContext) WithEncodeSet(ctx context.Context) context.Context {
	return w.Context
}
func (w *withContext) WithEncodeKey(ctx context.Context) context.Context {
	return w.Context
}
func (w *withContext) WithDecodeSet(ctx context.Context) context.Context {
	return w.Context
}
func (w *withContext) WithDecodeKey(ctx context.Context) context.Context {
	return w.Context
}
func (w *withContext) WithFetchSet(ctx context.Context) context.Context {
	return w.Context
}
func (w *withContext) WithFetchKey(ctx context.Context) context.Context {
	return w.Context
}

// for
//     `OptionalFetchSet`,
//     `OptionalFetchKey`
func WithHTTPClient(hclt *http.Client) *withHTTPClient {
	return &withHTTPClient{
		Client: hclt,
	}
}
func (w *withHTTPClient) WithFetchSet(ctx context.Context) context.Context {
	var ifset *OptionFetchSet
	ctx = getContextValue(ctx, &ifset, true)
	ifset.Client = w.Client
	return ctx
}
func (w *withHTTPClient) WithFetchKey(ctx context.Context) context.Context {
	var ifkey *OptionFetchKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.Client = w.Client
	return ctx
}

// for
//     `OptionalFetchKey`
//     `OptionalDecodeKey`
func WithSelectByID(kid string) *withSelectByID {
	return &withSelectByID{
		kid: kid,
	}
}

func (w *withSelectByID) WithFetchKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.SelectByID = w.kid
	return ctx
}

func (w *withSelectByID) WithDecodeKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.SelectByID = w.kid
	return ctx
}

// for
//     `OptionalFetchSet`
//     `OptionalFetchKey`
//     `OptionalDecodeSet`
//     `OptionalDecodeKey`
func WithStrict(strict bool) *withStrict {
	return &withStrict{
		strict: strict,
	}
}
func (w *withStrict) WithFetchSet(ctx context.Context) context.Context {
	var ifset *OptionDecodeSet
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifset, true)
	ctx = getContextValue(ctx, &ifkey, true)
	ifset.Strict = w.strict
	ifkey.Strict = w.strict
	return ctx
}
func (w *withStrict) WithDecodeSet(ctx context.Context) context.Context {
	var ifset *OptionDecodeSet
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifset, true)
	ctx = getContextValue(ctx, &ifkey, true)
	ifset.Strict = w.strict
	ifkey.Strict = w.strict
	return ctx
}
func (w *withStrict) WithFetchKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.Strict = w.strict
	return ctx
}
func (w *withStrict) WithDecodeKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.Strict = w.strict
	return ctx
}

// for
//     `OptionalFetchSet`
//     `OptionalFetchKey`
//     `OptionalDecodeSet`
//     `OptionalDecodeKey`
func WithRecompute(recompute bool) *withRecompute {
	return &withRecompute{
		recompute: recompute,
	}
}

func (w *withRecompute) WithFetchSet(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.Recalculate = w.recompute
	return ctx
}
func (w *withRecompute) WithDecodeSet(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.Recalculate = w.recompute
	return ctx
}
func (w *withRecompute) WithFetchKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.Recalculate = w.recompute
	return ctx
}
func (w *withRecompute) WithDecodeKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = getContextValue(ctx, &ifkey, true)
	ifkey.Recalculate = w.recompute
	return ctx
}
