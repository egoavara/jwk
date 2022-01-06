package jwk_test

import (
	"testing"

	"github.com/egoavara/jwk"
)

func TestFetch(t *testing.T) {
	target := "https://www.googleapis.com/oauth2/v3/certs"
	s, err := jwk.FetchSet(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(s)
}
