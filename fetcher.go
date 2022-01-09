package jwk

import (
	"context"
	"net/url"
	"time"
)

type (
	Fetcher struct {
		//
		Location              *url.URL
		TTL                   time.Duration
		DefaultOnRefreshBegin func() context.Context
		DefaultOnRefreshAfter func(*DoneRefresh, *DoneRefresh) *DoneRefresh
		//
		prev *DoneRefresh
	}
	Refresh struct {
		Location        *url.URL
		MaxRequestCount uint8
		OnRefreshBegin  func() context.Context
		OnRefreshAfter  func(*DoneRefresh, *DoneRefresh) *DoneRefresh
	}
	DoneRefresh struct {
		Location *url.URL
		FetchAt  time.Time
		Set      *Set
		Error    error
	}
	OptionalFetcher interface{ WithFetcher(*Fetcher) }
	OptioanlRefresh interface{ WithRefresh(*Refresh) }

	OnRefreshBegin func() context.Context
	OnRefreshAfter func(*DoneRefresh, *DoneRefresh) *DoneRefresh
	WithTTL        time.Duration
)

func (fn OnRefreshBegin) WithFetcher(f *Fetcher) { f.DefaultOnRefreshBegin = fn }
func (fn OnRefreshAfter) WithFetcher(f *Fetcher) { f.DefaultOnRefreshAfter = fn }
func (fn OnRefreshBegin) WithRefresh(r *Refresh) { r.OnRefreshBegin = fn }
func (fn OnRefreshAfter) WithRefresh(r *Refresh) { r.OnRefreshAfter = fn }

// func (w WithTTL) WithFetcher(f *Fetcher) { f.DefaultOnRefreshAfter = fn }
// func (w WithTTL) WithRefresh(r *Refresh) { r.OnRefreshAfter = fn }

// NewFetcher
// urlloc MUST be valid url, or else return ERROR
func NewFetcher(urlloc interface{}, opts ...OptionalFetcher) (*Fetcher, error) {
	realurlloc, err := utilURL(urlloc)
	if err != nil {
		return nil, err
	}
	fet := LazyFetcher(realurlloc, opts...)
	_, err = fet.Refresh()
	if err != nil {
		return nil, err
	}
	return fet, nil
}

// LazyFetcher
// urlloc MUST be valid url, if not Fetcher.Location is nil, it may cause lose detail error inform
func LazyFetcher(urlloc interface{}, opts ...OptionalFetcher) *Fetcher {
	fet := &Fetcher{
		TTL:                   30 * time.Minute,
		DefaultOnRefreshBegin: nil,
		DefaultOnRefreshAfter: nil,
		prev:                  nil,
	}
	fet.Location, _ = utilURL(urlloc)
	for _, fo := range opts {
		fo.WithFetcher(fet)
	}
	return fet
}

// `MustGet` mean if there is no resourece from origin(cause by network error, or server down, or many reason), it return <nil>
// So if you want to use this, take responsibility
// If you want return NIL instead of PANIC, try `Should`
func (fet *Fetcher) MustGet(opts ...OptioanlRefresh) *Set {
	if s, err := fet.Get(); err != nil {
		return nil
	} else {
		return s
	}
}

func (fet *Fetcher) Get(opts ...OptioanlRefresh) (*Set, error) {
	if fet.prev == nil || time.Now().After(fet.prev.FetchAt.Add(fet.TTL)) {
		return fet.Refresh(opts...)
	}
	return fet.prev.Set, fet.prev.Error
}

func (fet *Fetcher) Cached() *Set {
	if fet.prev == nil {
		return nil
	}
	return fet.prev.Set
}

func (fet *Fetcher) DetailCached() *DoneRefresh {
	return fet.prev
}

func (fet *Fetcher) Refresh(opts ...OptioanlRefresh) (*Set, error) {
	refresh := &Refresh{
		Location:        fet.Location.ResolveReference(new(url.URL)),
		MaxRequestCount: 0,
		OnRefreshBegin:  fet.DefaultOnRefreshBegin,
		OnRefreshAfter:  fet.DefaultOnRefreshAfter,
	}
	for _, ro := range opts {
		ro.WithRefresh(refresh)
	}
	if refresh.OnRefreshBegin == nil {
		refresh.OnRefreshBegin = context.Background
	}
	if refresh.OnRefreshAfter == nil {
		refresh.OnRefreshAfter = func(rd1, rd2 *DoneRefresh) *DoneRefresh { return rd2 }
	}
	var curr = fet.doRefresh(refresh)
	for i := 0; curr == nil && i < int(refresh.MaxRequestCount); i++ {
		curr = fet.doRefresh(refresh)
	}
	if curr == nil {
		refresh.OnRefreshAfter = func(rd1, rd2 *DoneRefresh) *DoneRefresh { return rd2 }
		curr = fet.doRefresh(refresh)
	}
	fet.prev = curr
	return fet.prev.Set, fet.prev.Error
}

func (fet *Fetcher) doRefresh(refresh *Refresh) *DoneRefresh {
	next := &DoneRefresh{
		Location: fet.Location.ResolveReference(new(url.URL)),
		FetchAt:  time.Now(),
	}
	next.Set, next.Error = FetchSetBy(refresh.OnRefreshBegin(), refresh.Location)
	return refresh.OnRefreshAfter(fet.prev, next)
}
