package jwk_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/egoavara/jwk"
)

func TestContext(t *testing.T) {
	// check load/store for jwk.OptionDecodeKey
	{
		ctx := context.Background()
		{
			var opt *jwk.OptionDecodeKey
			ctx = jwk.MustGetOptionFromContext(ctx, &opt, true)
			opt.AllowUnknownField = true
		}
		{
			var opt *jwk.OptionDecodeKey
			jwk.MustGetOptionFromContext(ctx, &opt, false)
			if opt.AllowUnknownField != true {
				t.Fatal("OptionDecodeKey : AllowUnknownField must be true")
			}
		}
	}

	// check load/store for  jwk.OptionDecodeSet
	{
		ctx := context.Background()
		{
			var opt *jwk.OptionDecodeSet
			ctx = jwk.MustGetOptionFromContext(ctx, &opt, true)
			opt.DisallowUnknownField = true
		}
		{
			var opt *jwk.OptionDecodeSet
			jwk.MustGetOptionFromContext(ctx, &opt, false)
			if opt.DisallowUnknownField != true {
				t.Fatal("OptionDecodeSet : DisallowUnknownField must be true")
			}
		}
	}

	// check load/store for jwk.OptionEncodeSet
	{
		ctx := context.Background()
		{
			var opt *jwk.OptionEncodeSet
			ctx = jwk.MustGetOptionFromContext(ctx, &opt, true)
			opt.DisallowUnknownField = true
		}
		{
			var opt *jwk.OptionEncodeSet
			jwk.MustGetOptionFromContext(ctx, &opt, false)
			if opt.DisallowUnknownField != true {
				t.Fatal("OptionEncodeSet : DisallowUnknownField must be true")
			}
		}
	}

	// check load/store for jwk.OptionEncodeKey
	{
		ctx := context.Background()
		{
			var opt *jwk.OptionEncodeKey
			ctx = jwk.MustGetOptionFromContext(ctx, &opt, true)
			opt.DisallowUnknownField = true
		}
		{
			var opt *jwk.OptionEncodeKey
			jwk.MustGetOptionFromContext(ctx, &opt, false)
			if opt.DisallowUnknownField != true {
				t.Fatal("OptionEncodeKey : DisallowUnknownField must be true")
			}
		}
	}

	// check load/store for jwk.OptionFetch
	{
		ctx := context.Background()
		{
			var opt *jwk.OptionFetch
			ctx = jwk.MustGetOptionFromContext(ctx, &opt, true)
			opt.Client = nil
		}
		{
			var opt *jwk.OptionFetch
			jwk.MustGetOptionFromContext(ctx, &opt, false)
			if opt.Client != nil {
				t.Fatal("OptionFetch : Client must be nil")
			}
		}
	}
}

func TestWiths(t *testing.T) {
	t.Run("WithContext", func(t *testing.T) {
		trg := context.Background()
		if jwk.WithContext(trg).WithDecodeKey(context.Background()) != trg {
			t.Fatalf("expected %v, but not got", trg)
		}
		if jwk.WithContext(trg).WithDecodeSet(context.Background()) != trg {
			t.Fatalf("expected %v, but not got", trg)
		}
		if jwk.WithContext(trg).WithEncodeKey(context.Background()) != trg {
			t.Fatalf("expected %v, but not got", trg)
		}
		if jwk.WithContext(trg).WithEncodeSet(context.Background()) != trg {
			t.Fatalf("expected %v, but not got", trg)
		}
		if jwk.WithContext(trg).WithFetchKey(context.Background()) != trg {
			t.Fatalf("expected %v, but not got", trg)
		}
		if jwk.WithContext(trg).WithFetchSet(context.Background()) != trg {
			t.Fatalf("expected %v, but not got", trg)
		}
	})
	t.Run("WithHTTPClient", func(t *testing.T) {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		var clt = &http.Client{
			Jar: jar,
		}
		clt.Jar.SetCookies(
			&url.URL{
				Scheme:  "http",
				Host:    "www.me.com",
				Path:    "/",
				RawPath: "/",
			},
			[]*http.Cookie{{
				Name:  "TEST",
				Value: "VALUE",
			}},
		)
		// before modify option
		var optdef *jwk.OptionFetch
		var optwfk *jwk.OptionFetch
		var optwfs *jwk.OptionFetch
		jwk.MustGetOptionFromContext(context.Background(), &optdef, false)
		jwk.MustGetOptionFromContext(jwk.WithHTTPClient(clt).WithFetchSet(context.Background()), &optwfk, true)
		jwk.MustGetOptionFromContext(jwk.WithHTTPClient(clt).WithFetchKey(context.Background()), &optwfs, true)
		if optdef.Client != http.DefaultClient {
			t.Fatalf("jwk.OptionFetch.Client must be http.DefaultClient")
		}
		if optwfk.Client != clt {
			t.Fatalf("jwk.OptionFetch.Client must be %v", clt)
		}
		if optwfs.Client != clt {
			t.Fatalf("jwk.OptionFetch.Client must be %v", clt)
		}

	})
	t.Run("WithSelector", func(t *testing.T) {
		const EXPECTED_VALUE = "EXPECTED ID"
		handle := func(k jwk.Key) bool {
			return k.Kid() == EXPECTED_VALUE
		}
		{
			var opt *jwk.OptionDecodeKey
			jwk.MustGetOptionFromContext(
				jwk.WithSelector(handle).WithDecodeKey(context.Background()),
				&opt,
				false,
			)
			if !opt.Selector(&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: EXPECTED_VALUE}}) {
				t.Fatalf("not expected result for OptionDecodeKey.Selector")
			}
		}
		{
			var opt *jwk.OptionDecodeKey
			jwk.MustGetOptionFromContext(
				jwk.WithSelector(handle).WithFetchKey(context.Background()),
				&opt,
				false,
			)
			if !opt.Selector(&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: EXPECTED_VALUE}}) {
				t.Fatalf("not expected result for OptionDecodeKey.Selector")
			}
		}
	})
	t.Run("WithHandleID", func(t *testing.T) {
		var EXPECTED_VALUE = "EXPECTED ID"
		handle := func(s *string) *string {
			return &EXPECTED_VALUE
		}
		{
			var opt *jwk.OptionDecodeKey
			jwk.MustGetOptionFromContext(
				jwk.WithHandleID(handle).WithDecodeKey(context.Background()),
				&opt,
				false,
			)
			if opt.HandleID(nil) != &EXPECTED_VALUE {
				t.Fatalf("not expected result for OptionDecodeKey.HandleID")
			}
		}
		{
			var opt *jwk.OptionDecodeKey
			jwk.MustGetOptionFromContext(
				jwk.WithHandleID(handle).WithDecodeSet(context.Background()),
				&opt,
				false,
			)
			if opt.HandleID(nil) != &EXPECTED_VALUE {
				t.Fatalf("not expected result for OptionDecodeKey.HandleID")
			}
		}
		{
			var opt *jwk.OptionDecodeKey
			jwk.MustGetOptionFromContext(
				jwk.WithHandleID(handle).WithFetchKey(context.Background()),
				&opt,
				false,
			)
			if opt.HandleID(nil) != &EXPECTED_VALUE {
				t.Fatalf("not expected result for OptionDecodeKey.HandleID")
			}
		}
		{
			var opt *jwk.OptionDecodeKey
			jwk.MustGetOptionFromContext(
				jwk.WithHandleID(handle).WithFetchSet(context.Background()),
				&opt,
				false,
			)
			if opt.HandleID(nil) != &EXPECTED_VALUE {
				t.Fatalf("not expected result for OptionDecodeKey.HandleID")
			}
		}

	})
	t.Run("WithOptionEncodeSet", func(t *testing.T) {
		var option *jwk.OptionEncodeSet
		jwk.MustGetOptionFromContext(
			jwk.WithOptionEncodeSet(func(value *jwk.OptionEncodeSet) { value.DisallowUnknownField = true }).WithEncodeSet(context.Background()),
			&option, false,
		)
		if option.DisallowUnknownField != true {
			t.Fatalf("unexpected value %v", option.DisallowUnknownField)
		}
	})
	t.Run("WithOptionEncodeKey", func(t *testing.T) {
		{
			var option *jwk.OptionEncodeKey
			jwk.MustGetOptionFromContext(
				jwk.WithOptionEncodeKey(func(value *jwk.OptionEncodeKey) { value.DisallowUnknownField = true }).WithEncodeSet(context.Background()),
				&option, false,
			)
			if option.DisallowUnknownField != true {
				t.Fatalf("unexpected value %v", option.DisallowUnknownField)
			}
		}
		{
			var option *jwk.OptionEncodeKey
			jwk.MustGetOptionFromContext(
				jwk.WithOptionEncodeKey(func(value *jwk.OptionEncodeKey) { value.DisallowUnknownField = true }).WithEncodeKey(context.Background()),
				&option, false,
			)
			if option.DisallowUnknownField != true {
				t.Fatalf("unexpected value %v", option.DisallowUnknownField)
			}
		}
	})
	t.Run("WithOptionDecodeKey", func(t *testing.T) {
		{
			var option *jwk.OptionDecodeKey
			jwk.MustGetOptionFromContext(
				jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) { value.AllowUnknownField = true }).WithDecodeKey(context.Background()),
				&option, false,
			)
			if option.AllowUnknownField != true {
				t.Fatalf("unexpected value %v", option.AllowUnknownField)
			}
		}
		{
			var option *jwk.OptionDecodeKey
			jwk.MustGetOptionFromContext(
				jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) { value.AllowUnknownField = true }).WithDecodeSet(context.Background()),
				&option, false,
			)
			if option.AllowUnknownField != true {
				t.Fatalf("unexpected value %v", option.AllowUnknownField)
			}
		}
		{
			var option *jwk.OptionDecodeKey
			jwk.MustGetOptionFromContext(
				jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) { value.AllowUnknownField = true }).WithFetchKey(context.Background()),
				&option, false,
			)
			if option.AllowUnknownField != true {
				t.Fatalf("unexpected value %v", option.AllowUnknownField)
			}
		}
		{
			var option *jwk.OptionDecodeKey
			jwk.MustGetOptionFromContext(
				jwk.WithOptionDecodeKey(func(value *jwk.OptionDecodeKey) { value.AllowUnknownField = true }).WithFetchSet(context.Background()),
				&option, false,
			)
			if option.AllowUnknownField != true {
				t.Fatalf("unexpected value %v", option.AllowUnknownField)
			}
		}
	})
	t.Run("WithOptionDecodeSet", func(t *testing.T) {
		{
			var option *jwk.OptionDecodeSet
			jwk.MustGetOptionFromContext(
				jwk.WithOptionDecodeSet(func(value *jwk.OptionDecodeSet) { value.DisallowUnknownField = true }).WithDecodeSet(context.Background()),
				&option, false,
			)
			if option.DisallowUnknownField != true {
				t.Fatalf("unexpected value %v", option.DisallowUnknownField)
			}
		}
		{
			var option *jwk.OptionDecodeSet
			jwk.MustGetOptionFromContext(
				jwk.WithOptionDecodeSet(func(value *jwk.OptionDecodeSet) { value.DisallowUnknownField = true }).WithFetchSet(context.Background()),
				&option, false,
			)
			if option.DisallowUnknownField != true {
				t.Fatalf("unexpected value %v", option.DisallowUnknownField)
			}
		}
	})
	t.Run("WithOptionFetch", func(t *testing.T) {
		{
			var option *jwk.OptionFetch
			jwk.MustGetOptionFromContext(
				jwk.WithOptionFetch(func(value *jwk.OptionFetch) { value.Client = nil }).WithFetchKey(context.Background()),
				&option, false,
			)
			if option.Client != nil {
				t.Fatalf("expected value <nil>, but got %v", option.Client)
			}
		}
		{
			var option *jwk.OptionFetch
			jwk.MustGetOptionFromContext(
				jwk.WithOptionFetch(func(value *jwk.OptionFetch) { value.Client = nil }).WithFetchSet(context.Background()),
				&option, false,
			)
			if option.Client != nil {
				t.Fatalf("expected value <nil>, but got %v", option.Client)
			}
		}
	})

}
func TestOptionAsContext(t *testing.T) {
	t.Run("OptionDecodeKey", func(t *testing.T) {
		var option *jwk.OptionDecodeKey
		jwk.MustGetOptionFromContext(&jwk.OptionDecodeKey{AllowUnknownField: true}, &option, false)
		if option.AllowUnknownField != true {
			t.Fatalf("expect value true, but got %v", option.AllowUnknownField)
		}
	})
	t.Run("OptionDecodeSet", func(t *testing.T) {
		var option *jwk.OptionDecodeSet
		jwk.MustGetOptionFromContext(&jwk.OptionDecodeSet{DisallowUnknownField: true}, &option, false)
		if option.DisallowUnknownField != true {
			t.Fatalf("expect value true, but got %v", option.DisallowUnknownField)
		}
	})
	t.Run("OptionEncodeKey", func(t *testing.T) {
		var option *jwk.OptionEncodeKey
		jwk.MustGetOptionFromContext(&jwk.OptionEncodeKey{DisallowUnknownField: true}, &option, false)
		if option.DisallowUnknownField != true {
			t.Fatalf("expect value true, but got %v", option.DisallowUnknownField)
		}
	})
	t.Run("OptionEncodeSet", func(t *testing.T) {
		var option *jwk.OptionEncodeSet
		jwk.MustGetOptionFromContext(&jwk.OptionEncodeSet{DisallowUnknownField: true}, &option, false)
		if option.DisallowUnknownField != true {
			t.Fatalf("expect value true, but got %v", option.DisallowUnknownField)
		}
	})
	t.Run("OptionFetch", func(t *testing.T) {
		var option *jwk.OptionFetch
		jwk.MustGetOptionFromContext(&jwk.OptionFetch{Client: nil}, &option, false)
		if option.Client != nil {
			t.Fatalf("expect value <nil>, but got %v", option.Client)
		}
	})
}
func TestContextInterface(t *testing.T) {
	{
		opt := &jwk.OptionDecodeKey{}
		tm := time.Time{}
		if a, b := opt.Deadline(); a != tm && b != false {
			t.Fatalf("expect value (%v, false), but got (%v, %v)", tm, a, b)
		}
		if done := opt.Done(); done != nil {
			t.Fatalf("expect value <nil>, but got %v", done)
		}
		if err := opt.Err(); err != nil {
			t.Fatalf("expect value <nil>, but got %v", err)
		}
		if val := opt.Value(nil); val != nil {
			t.Fatalf("expect value <nil>, but got %v", val)
		}
		if val := opt.Value(reflect.TypeOf(&opt)); val == nil {
			t.Fatalf("expect value not <nil>, but got <nil>")
		}
	}
	{
		opt := &jwk.OptionDecodeSet{}
		tm := time.Time{}
		if a, b := opt.Deadline(); a != tm && b != false {
			t.Fatalf("expect value (%v, false), but got (%v, %v)", tm, a, b)
		}
		if done := opt.Done(); done != nil {
			t.Fatalf("expect value <nil>, but got %v", done)
		}
		if err := opt.Err(); err != nil {
			t.Fatalf("expect value <nil>, but got %v", err)
		}
		if val := opt.Value(nil); val != nil {
			t.Fatalf("expect value <nil>, but got %v", val)
		}
		if val := opt.Value(reflect.TypeOf(&opt)); val == nil {
			t.Fatalf("expect value not <nil>, but got <nil>")
		}
		{
			opt := &jwk.OptionEncodeKey{}
			tm := time.Time{}
			if a, b := opt.Deadline(); a != tm && b != false {
				t.Fatalf("expect value (%v, false), but got (%v, %v)", tm, a, b)
			}
			if done := opt.Done(); done != nil {
				t.Fatalf("expect value <nil>, but got %v", done)
			}
			if err := opt.Err(); err != nil {
				t.Fatalf("expect value <nil>, but got %v", err)
			}
			if val := opt.Value(nil); val != nil {
				t.Fatalf("expect value <nil>, but got %v", val)
			}
			if val := opt.Value(reflect.TypeOf(&opt)); val == nil {
				t.Fatalf("expect value not <nil>, but got <nil>")
			}
		}
	}
	{
		opt := &jwk.OptionDecodeSet{}
		tm := time.Time{}
		if a, b := opt.Deadline(); a != tm && b != false {
			t.Fatalf("expect value (%v, false), but got (%v, %v)", tm, a, b)
		}
		if done := opt.Done(); done != nil {
			t.Fatalf("expect value <nil>, but got %v", done)
		}
		if err := opt.Err(); err != nil {
			t.Fatalf("expect value <nil>, but got %v", err)
		}
		if val := opt.Value(nil); val != nil {
			t.Fatalf("expect value <nil>, but got %v", val)
		}
		if val := opt.Value(reflect.TypeOf(&opt)); val == nil {
			t.Fatalf("expect value not <nil>, but got <nil>")
		}
		{
			opt := &jwk.OptionEncodeSet{}
			tm := time.Time{}
			if a, b := opt.Deadline(); a != tm && b != false {
				t.Fatalf("expect value (%v, false), but got (%v, %v)", tm, a, b)
			}
			if done := opt.Done(); done != nil {
				t.Fatalf("expect value <nil>, but got %v", done)
			}
			if err := opt.Err(); err != nil {
				t.Fatalf("expect value <nil>, but got %v", err)
			}
			if val := opt.Value(nil); val != nil {
				t.Fatalf("expect value <nil>, but got %v", val)
			}
			if val := opt.Value(reflect.TypeOf(&opt)); val == nil {
				t.Fatalf("expect value not <nil>, but got <nil>")
			}
		}
		{
			opt := &jwk.OptionFetch{}
			tm := time.Time{}
			if a, b := opt.Deadline(); a != tm && b != false {
				t.Fatalf("expect value (%v, false), but got (%v, %v)", tm, a, b)
			}
			if done := opt.Done(); done != nil {
				t.Fatalf("expect value <nil>, but got %v", done)
			}
			if err := opt.Err(); err != nil {
				t.Fatalf("expect value <nil>, but got %v", err)
			}
			if val := opt.Value(nil); val != nil {
				t.Fatalf("expect value <nil>, but got %v", val)
			}
			if val := opt.Value(reflect.TypeOf(&opt)); val == nil {
				t.Fatalf("expect value not <nil>, but got <nil>")
			}
		}
	}
}
