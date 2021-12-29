package jwk

import (
	"context"
	"net/http"
)

type ctxKey string

const (
	ctxJSONStrict           ctxKey = "ctxJSONStrict"
	ctxRecompute            ctxKey = "ctxRecompute"
	ctxNoValidate           ctxKey = "ctxNoValidate"
	ctxKeyID                ctxKey = "ctxKeyID"
	ctxHTTPClient           ctxKey = "ctxHTTPClient"
	ctxFromSetToKeys        ctxKey = "ctxFromSetToKeys"
	ctxOneOrMoreKeySelector ctxKey = "ctxOneOrMoreKeySelector"
)

type HandleContext interface {
	HandleContext(context.Context) context.Context
}

type FnHandleContext struct {
	Fn func(context.Context) context.Context
}

func (fnhctx *FnHandleContext) HandleContext(ctx context.Context) context.Context {
	return fnhctx.Fn(ctx)
}
func reduceContext(ctx context.Context, handlers ...HandleContext) context.Context {
	for _, handler := range handlers {
		ctx = handler.HandleContext(ctx)
	}
	return ctx
}

// for any
func WithContext(overide context.Context) HandleContext {
	return &FnHandleContext{Fn: func(c context.Context) context.Context { return overide }}
}

// for
//     `HandleFetchKeyConfig`,
//     `HandleFetchKeysConfig`
//     `HandleFetchSetConfig`
func WithHTTPClient(hclt *http.Client) HandleContext {
	return &FnHandleContext{Fn: func(c context.Context) context.Context { return context.WithValue(c, ctxHTTPClient, hclt) }}
}

// for
//     `HandleFetchKeyConfig`
//     `HandleFetchKeysConfig`
// mutually exclusive
//     `WithKeySelector`
//     `WithKeysSelector`
func WithKeySelector(kid string) HandleContext {
	return &FnHandleContext{Fn: func(c context.Context) context.Context {
		return context.WithValue(c, ctxOneOrMoreKeySelector, kid)
	}}
}

// for
//     `HandleFetchKeyConfig`
//     `HandleFetchKeysConfig`
// mutually exclusive
//     `WithKeySelector`
//     `WithKeysSelector`
func WithKeysSelector(kids ...string) HandleContext {
	return &FnHandleContext{Fn: func(c context.Context) context.Context { return context.WithValue(c, ctxOneOrMoreKeySelector, kids) }}
}

// for
//     `HandleFetchKeyConfig`
//     `HandleFetchKeysConfig`
func WithStrict(strict bool) HandleContext {
	return &FnHandleContext{Fn: func(c context.Context) context.Context { return context.WithValue(c, ctxJSONStrict, strict) }}
}

// for
//     `HandleFetchKeyConfig`
//     `HandleFetchKeysConfig`
func WithRecompute(recompute bool) HandleContext {
	return &FnHandleContext{Fn: func(c context.Context) context.Context { return context.WithValue(c, ctxRecompute, recompute) }}
}
