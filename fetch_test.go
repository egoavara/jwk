package jwk_test

import (
	_ "embed"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/egoavara/jwk"
)

var (
	//go:embed embeding/preload-googleapis-oauth2-v3-cert.json
	googleapisOAuth2V3Cert string
)

func TestFetch(t *testing.T) {
	t.Run("googleapis", func(t *testing.T) {
		target := "https://www.googleapis.com/oauth2/v3/certs"
		s, err := jwk.FetchSet(target)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		pres, err := jwk.DecodeSet(strings.NewReader(googleapisOAuth2V3Cert))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		if !reflect.DeepEqual(s, pres) {
			t.Fatalf("expected %#v equal %#v, but not", s, pres)
		}
	})
	t.Run("with custom client", func(t *testing.T) {
		target := "https://www.googleapis.com/oauth2/v3/certs"
		_, err := jwk.FetchSet(target, jwk.WithHTTPClient(&http.Client{
			Timeout: time.Second,
		}))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
	})
	t.Run("get key", func(t *testing.T) {
		target := "https://www.googleapis.com/oauth2/v3/certs"
		_, err := jwk.FetchKey(target, jwk.WithSelector(func(k jwk.Key) bool { return true }))
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
	})
	t.Run("404 set", func(t *testing.T) {
		target := "https://www.googleapis.com/oauth2/v3/certs404"
		_, err := jwk.FetchSet(target)
		if !errors.Is(err, jwk.ErrHTTPRequest) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrHTTPRequest)
		}
	})
	t.Run("404 key", func(t *testing.T) {
		target := "https://www.googleapis.com/oauth2/v3/certs404"
		_, err := jwk.FetchKey(target, jwk.WithSelector(func(k jwk.Key) bool { return true }))
		if !errors.Is(err, jwk.ErrHTTPRequest) {
			t.Fatalf("expected %v is %v, but not", err, jwk.ErrHTTPRequest)
		}
	})
}
