package jwk

import (
	"context"
	"net/url"
	"sync"
	"time"
)

type (
	Fetcher struct {
		//
		Location              *url.URL
		Interval              time.Duration
		DefaultOnRefreshBegin func() context.Context
		DefaultOnRefreshAfter func(*DoneRefresh, *DoneRefresh) *DoneRefresh
		//
		prev *DoneRefresh
		next time.Time
		mtx  *sync.RWMutex
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
	FetcherOption interface{ HandleFetcher(*Fetcher) }
	RefreshOption interface{ HandleRefresh(*Refresh) }

	OnRefreshBegin func() context.Context
	OnRefreshAfter func(*DoneRefresh, *DoneRefresh) *DoneRefresh
)

func (fn OnRefreshBegin) HandleFetcher(f *Fetcher) { f.DefaultOnRefreshBegin = fn }
func (fn OnRefreshAfter) HandleFetcher(f *Fetcher) { f.DefaultOnRefreshAfter = fn }
func (fn OnRefreshBegin) HandleRefresh(r *Refresh) { r.OnRefreshBegin = fn }
func (fn OnRefreshAfter) HandleRefresh(r *Refresh) { r.OnRefreshAfter = fn }

// NewFetcher
// urlloc MUST be valid url, or else return ERROR
func NewFetcher(urlloc interface{}, opts ...FetcherOption) (*Fetcher, error) {
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
func LazyFetcher(urlloc interface{}, opts ...FetcherOption) *Fetcher {
	fet := &Fetcher{
		Interval:              30 * time.Minute,
		DefaultOnRefreshBegin: nil,
		DefaultOnRefreshAfter: nil,
		prev:                  nil,
		next:                  time.Now(),
		mtx:                   new(sync.RWMutex),
	}
	fet.Location, _ = utilURL(urlloc)
	for _, fo := range opts {
		fo.HandleFetcher(fet)
	}
	return fet
}

// `MustGet` mean if there is no resourece from origin(cause by network error, or server down, or many reason), it return PANIC!
// So if you want to use this, take responsibility
// If you want return NIL instead of PANIC, try `Should`
func (fet *Fetcher) MustGet(opts ...RefreshOption) *Set {
	if s, err := fet.Get(); err != nil {
		panic(err)
	} else {
		return s
	}
}

// `ShouldGet` mean if refresh is failed,
func (fet *Fetcher) ShouldGet(opts ...RefreshOption) *Set {
	if s, err := fet.Get(); err != nil {
		return nil
	} else {
		return s
	}
}

func (fet *Fetcher) Get(opts ...RefreshOption) (*Set, error) {
	if fet.prev == nil || time.Now().After(fet.next) {
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

func (fet *Fetcher) Refresh(opts ...RefreshOption) (*Set, error) {
	refresh := &Refresh{
		Location:        fet.Location.ResolveReference(new(url.URL)),
		MaxRequestCount: 0,
		OnRefreshBegin:  fet.DefaultOnRefreshBegin,
		OnRefreshAfter:  fet.DefaultOnRefreshAfter,
	}
	for _, ro := range opts {
		ro.HandleRefresh(refresh)
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
