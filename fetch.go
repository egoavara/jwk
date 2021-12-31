package jwk

import (
	"context"
	"net/http"
)

func FetchKey(url interface{}, options ...OptionalFetchKey) (Key, error) {
	ctx := context.Background()
	for _, option := range options {
		ctx = option.WithFetchKey(ctx)
	}
	return FetchKeyBy(ctx, url)
}

func FetchSet(url interface{}, options ...OptionalFetchSet) (s *Set, err error) {
	ctx := context.Background()
	for _, option := range options {
		ctx = option.WithFetchSet(ctx)
	}
	return FetchSetBy(ctx, url)
}

func FetchKeyBy(ctx context.Context, urlloc interface{}) (Key, error) {
	var option *OptionFetch
	getContextValue(ctx, &option, false)
	//
	rurlloc, err := utilURL(urlloc)
	if err != nil {
		return nil, wrapDetail(ErrInvalidURL, err)
	}
	res, err := utilResponse(rurlloc, ctx, option.Client)
	if err != nil {
		return nil, wrapDetail(ErrHTTPRequest, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, wrapDetailf(ErrHTTPRequest, "unexpected status code %d", res.StatusCode)
	}
	return DecodeKeyBy(ctx, res.Body)
}

func FetchSetBy(ctx context.Context, urlloc interface{}) (*Set, error) {
	var option *OptionFetch
	getContextValue(ctx, &option, false)
	//
	rurlloc, err := utilURL(urlloc)
	if err != nil {
		return nil, wrapDetail(ErrInvalidURL, err)
	}
	res, err := utilResponse(rurlloc, ctx, option.Client)
	if err != nil {
		return nil, wrapDetail(ErrHTTPRequest, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, wrapDetailf(ErrHTTPRequest, "unexpected status code %d", res.StatusCode)
	}
	return DecodeSetBy(ctx, res.Body)
}
