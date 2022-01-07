package jwk

import (
	"context"
	"net/http"
	"reflect"
	"time"
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
	withOptionEncodeSet struct{ handle func(*OptionEncodeSet) }
	withOptionEncodeKey struct{ handle func(*OptionEncodeKey) }
	withOptionDecodeSet struct{ handle func(*OptionDecodeSet) }
	withOptionDecodeKey struct{ handle func(*OptionDecodeKey) }
	withOptionFetch     struct{ handle func(*OptionFetch) }
	withContext         struct{ context context.Context }
	withHTTPClient      struct{ clt *http.Client }
	withSelector        struct{ selector func(Key) bool }
	withHandleID        struct{ handleID func(*string) *string }
)

// utility function for context
// ppoption must be one of (**OptionEncodeSet|**OptionEncodeKey|**OptionDecodeSet|**OptionDecodeKey|**OptionFetch)
// If there is no Option* in context, it return default option, not <nil>
// remind, ppoption must be pointer of pointer for example
//		var opt *OptionFetch
//		MustGetOptionFromContext(ctx, &opt, false)
func MustGetOptionFromContext(ctx context.Context, ppoption interface{}, orInsert bool) context.Context {
	reflectCTXType := reflect.TypeOf(ppoption)
	switch ctxv := ppoption.(type) {
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
			Client: http.DefaultClient,
		}
		if orInsert {
			ctx = context.WithValue(ctx, reflectCTXType, *ctxv)
		}
	}
	return ctx
}

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
	ctx = MustGetOptionFromContext(ctx, &ifset, true)
	ifset.Client = w.clt
	return ctx
}
func (w *withHTTPClient) WithFetchKey(ctx context.Context) context.Context {
	var ifkey *OptionFetch
	ctx = MustGetOptionFromContext(ctx, &ifkey, true)
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
	ctx = MustGetOptionFromContext(ctx, &ifkey, true)
	ifkey.Selector = w.selector
	return ctx
}

func (w *withSelector) WithDecodeKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = MustGetOptionFromContext(ctx, &ifkey, true)
	ifkey.Selector = w.selector
	return ctx
}

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
	ctx = MustGetOptionFromContext(ctx, &ifkey, true)
	ifkey.HandleID = w.handleID
	return ctx
}

func (w *withHandleID) WithDecodeSet(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = MustGetOptionFromContext(ctx, &ifkey, true)
	ifkey.HandleID = w.handleID
	return ctx
}

func (w *withHandleID) WithFetchKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = MustGetOptionFromContext(ctx, &ifkey, true)
	ifkey.HandleID = w.handleID
	return ctx
}

func (w *withHandleID) WithDecodeKey(ctx context.Context) context.Context {
	var ifkey *OptionDecodeKey
	ctx = MustGetOptionFromContext(ctx, &ifkey, true)
	ifkey.HandleID = w.handleID
	return ctx
}

func WithOptionEncodeSet(handle func(value *OptionEncodeSet)) *withOptionEncodeSet {
	return &withOptionEncodeSet{handle: handle}
}

func (w *withOptionEncodeSet) WithEncodeSet(ctx context.Context) context.Context {
	var option *OptionEncodeSet
	ctx = MustGetOptionFromContext(ctx, &option, true)
	w.handle(option)
	return ctx
}

func WithOptionEncodeKey(handle func(value *OptionEncodeKey)) *withOptionEncodeKey {
	return &withOptionEncodeKey{handle: handle}
}

func (w *withOptionEncodeKey) WithEncodeSet(ctx context.Context) context.Context {
	var option *OptionEncodeKey
	ctx = MustGetOptionFromContext(ctx, &option, true)
	w.handle(option)
	return ctx
}

func (w *withOptionEncodeKey) WithEncodeKey(ctx context.Context) context.Context {
	var option *OptionEncodeKey
	ctx = MustGetOptionFromContext(ctx, &option, true)
	w.handle(option)
	return ctx
}

func WithOptionDecodeSet(handle func(value *OptionDecodeSet)) *withOptionDecodeSet {
	return &withOptionDecodeSet{handle: handle}
}

func (w *withOptionDecodeSet) WithFetchSet(ctx context.Context) context.Context {
	var option *OptionDecodeSet
	ctx = MustGetOptionFromContext(ctx, &option, true)
	w.handle(option)
	return ctx
}

func (w *withOptionDecodeSet) WithDecodeSet(ctx context.Context) context.Context {
	var option *OptionDecodeSet
	ctx = MustGetOptionFromContext(ctx, &option, true)
	w.handle(option)
	return ctx
}

func WithOptionDecodeKey(handle func(value *OptionDecodeKey)) *withOptionDecodeKey {
	return &withOptionDecodeKey{handle: handle}
}

func (w *withOptionDecodeKey) WithFetchSet(ctx context.Context) context.Context {
	var option *OptionDecodeKey
	ctx = MustGetOptionFromContext(ctx, &option, true)
	w.handle(option)
	return ctx
}

func (w *withOptionDecodeKey) WithFetchKey(ctx context.Context) context.Context {
	var option *OptionDecodeKey
	ctx = MustGetOptionFromContext(ctx, &option, true)
	w.handle(option)
	return ctx
}

func (w *withOptionDecodeKey) WithDecodeSet(ctx context.Context) context.Context {
	var option *OptionDecodeKey
	ctx = MustGetOptionFromContext(ctx, &option, true)
	w.handle(option)
	return ctx
}

func (w *withOptionDecodeKey) WithDecodeKey(ctx context.Context) context.Context {
	var option *OptionDecodeKey
	ctx = MustGetOptionFromContext(ctx, &option, true)
	w.handle(option)
	return ctx
}

func WithOptionFetch(handle func(value *OptionFetch)) *withOptionFetch {
	return &withOptionFetch{handle: handle}
}

func (w *withOptionFetch) WithFetchSet(ctx context.Context) context.Context {
	var option *OptionFetch
	ctx = MustGetOptionFromContext(ctx, &option, true)
	w.handle(option)
	return ctx
}

func (w *withOptionFetch) WithFetchKey(ctx context.Context) context.Context {
	var option *OptionFetch
	ctx = MustGetOptionFromContext(ctx, &option, true)
	w.handle(option)
	return ctx
}

// context.Context for *OptionDecodeKey
func (opt *OptionDecodeKey) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

// context.Context for *OptionDecodeKey
func (opt *OptionDecodeKey) Done() <-chan struct{} {
	return nil
}

// context.Context for *OptionDecodeKey
func (opt *OptionDecodeKey) Err() error {
	return nil
}

// context.Context for *OptionDecodeKey
func (opt *OptionDecodeKey) Value(key interface{}) interface{} {
	if typ, ok := key.(reflect.Type); ok {
		if typ == reflect.TypeOf(&opt) {
			return opt
		}
	}
	return nil
}

// context.Context for *OptionDecodeSet
func (opt *OptionDecodeSet) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

// context.Context for *OptionDecodeSet
func (opt *OptionDecodeSet) Done() <-chan struct{} {
	return nil
}

// context.Context for *OptionDecodeSet
func (opt *OptionDecodeSet) Err() error {
	return nil
}

// context.Context for *OptionDecodeSet
func (opt *OptionDecodeSet) Value(key interface{}) interface{} {
	if typ, ok := key.(reflect.Type); ok {
		if typ == reflect.TypeOf(&opt) {
			return opt
		}
	}
	return nil
}

// context.Context for *OptionEncodeSet
func (opt *OptionEncodeSet) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

// context.Context for *OptionEncodeSet
func (opt *OptionEncodeSet) Done() <-chan struct{} {
	return nil
}

// context.Context for *OptionEncodeSet
func (opt *OptionEncodeSet) Err() error {
	return nil
}

// context.Context for *OptionEncodeSet
func (opt *OptionEncodeSet) Value(key interface{}) interface{} {
	if typ, ok := key.(reflect.Type); ok {
		if typ == reflect.TypeOf(&opt) {
			return opt
		}
	}
	return nil
}

// context.Context for *OptionEncodeKey
func (opt *OptionEncodeKey) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

// context.Context for *OptionEncodeKey
func (opt *OptionEncodeKey) Done() <-chan struct{} {
	return nil
}

// context.Context for *OptionEncodeKey
func (opt *OptionEncodeKey) Err() error {
	return nil
}

// context.Context for *OptionEncodeKey
func (opt *OptionEncodeKey) Value(key interface{}) interface{} {
	if typ, ok := key.(reflect.Type); ok {
		if typ == reflect.TypeOf(&opt) {
			return opt
		}
	}
	return nil
}

// context.Context for *OptionFetch
func (opt *OptionFetch) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

// context.Context for *OptionFetch
func (opt *OptionFetch) Done() <-chan struct{} {
	return nil
}

// context.Context for *OptionFetch
func (opt *OptionFetch) Err() error {
	return nil
}

// context.Context for *OptionFetch
func (opt *OptionFetch) Value(key interface{}) interface{} {
	if typ, ok := key.(reflect.Type); ok {
		if typ == reflect.TypeOf(&opt) {
			return opt
		}
	}
	return nil
}
