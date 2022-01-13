package jwk_test

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/egoavara/jwk"
)

var (
	//go:embed embeding/preload-googleapis-oauth2-v3-cert.json
	GOOGLEAPIS_CERT string
)

func TestFetcher(t *testing.T) {
	const target = "https://www.googleapis.com/oauth2/v3/certs"
	var offline = jwk.MustDecodeSet(strings.NewReader(GOOGLEAPIS_CERT))
	t.Run("new", func(t *testing.T) {
		fet, err := jwk.NewFetcher(target)
		if err != nil {
			t.Fatalf("expected <nil>, but got %v", err)
		}
		online := fet.MustGet()
		if !reflect.DeepEqual(offline, online) {
			ja, _ := json.MarshalIndent(offline, "", "    ")
			jb, _ := json.MarshalIndent(online, "", "    ")
			t.Fatalf("expected %v equal %v, but not", string(ja), string(jb))
		}
	})
	t.Run("lazy", func(t *testing.T) {
		fet := jwk.LazyFetcher(target)
		if dc := fet.DetailCached(); dc != nil {
			t.Fatalf("expected <nil>, but got %v", dc)
		}
	})
	// t.Run("refresh", func(t *testing.T) {

	// })
	// t.Run("timeout reload", func(t *testing.T) {

	// })
}
