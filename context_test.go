package jwk_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"testing"

	"github.com/egoavara/jwk"
)

func TestWithContext(t *testing.T) {
	var ctx context.Context
	ctx = jwk.WithContext(context.WithValue(context.Background(), "A", "B")).WithDecodeKey(context.Background())
	if ctx.Value("A") != "B" {
		t.Errorf("expected ctx['A'] is 'B' but got %v", ctx.Value("A"))
	}
	ctx = jwk.WithContext(context.WithValue(context.Background(), "A", "B")).WithDecodeSet(context.Background())
	if ctx.Value("A") != "B" {
		t.Errorf("expected ctx['A'] is 'B' but got %v", ctx.Value("A"))
	}
	ctx = jwk.WithContext(context.WithValue(context.Background(), "A", "B")).WithEncodeKey(context.Background())
	if ctx.Value("A") != "B" {
		t.Errorf("expected ctx['A'] is 'B' but got %v", ctx.Value("A"))
	}
	ctx = jwk.WithContext(context.WithValue(context.Background(), "A", "B")).WithEncodeSet(context.Background())
	if ctx.Value("A") != "B" {
		t.Errorf("expected ctx['A'] is 'B' but got %v", ctx.Value("A"))
	}
	ctx = jwk.WithContext(context.WithValue(context.Background(), "A", "B")).WithFetchKey(context.Background())
	if ctx.Value("A") != "B" {
		t.Errorf("expected ctx['A'] is 'B' but got %v", ctx.Value("A"))
	}
	ctx = jwk.WithContext(context.WithValue(context.Background(), "A", "B")).WithFetchSet(context.Background())
	if ctx.Value("A") != "B" {
		t.Errorf("expected ctx['A'] is 'B' but got %v", ctx.Value("A"))
	}
}

func TestWithHTTPClient(t *testing.T) {
	var ctx context.Context
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	var testclt = &http.Client{
		Jar: jar,
	}
	var urlloc = &url.URL{
		Scheme:  "http",
		Host:    "www.me.com",
		Path:    "/",
		RawPath: "/",
	}
	testclt.Jar.SetCookies(urlloc, []*http.Cookie{{
		Name:  "TEST",
		Value: "VALUE",
	}})
	//
	var iffk *jwk.OptionFetchKey
	ctx = jwk.WithHTTPClient(testclt).WithFetchKey(context.Background())
	iffk = ctx.Value(reflect.TypeOf(&iffk)).(*jwk.OptionFetchKey)
	if iffk.Client.Jar.Cookies(urlloc)[0].Name != "TEST" {
		t.Errorf("expected TEST but got %s", iffk.Client.Jar.Cookies(urlloc)[0].Name)
	}
	if iffk.Client.Jar.Cookies(urlloc)[0].Value != "VALUE" {
		t.Errorf("expected VALUE but got %s", iffk.Client.Jar.Cookies(urlloc)[0].Value)
	}
	var iffs *jwk.OptionFetchSet
	ctx = jwk.WithHTTPClient(testclt).WithFetchSet(context.Background())
	iffs = ctx.Value(reflect.TypeOf(&iffs)).(*jwk.OptionFetchSet)
	if iffs.Client.Jar.Cookies(urlloc)[0].Name != "TEST" {
		t.Errorf("expected TEST but got %s", iffs.Client.Jar.Cookies(urlloc)[0].Name)
	}
	if iffs.Client.Jar.Cookies(urlloc)[0].Value != "VALUE" {
		t.Errorf("expected VALUE but got %s", iffs.Client.Jar.Cookies(urlloc)[0].Value)
	}
}
