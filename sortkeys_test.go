package jwk_test

import (
	"math/rand"
	"sort"
	"testing"

	"github.com/egoavara/jwk"
)

func TestSortkey(t *testing.T) {
	t.Run("name is different", func(t *testing.T) {
		data := []jwk.Key{
			&jwk.UnknownKey{
				BaseKey: jwk.BaseKey{
					KeyID: "D",
				},
				KeyType: jwk.KeyTypeOctet,
			},
			&jwk.UnknownKey{
				BaseKey: jwk.BaseKey{
					KeyID: "A",
				},
				KeyType: jwk.KeyTypeOctet,
			},
			&jwk.UnknownKey{
				BaseKey: jwk.BaseKey{
					KeyID: "B",
				},
				KeyType: jwk.KeyTypeOctet,
			},
			&jwk.UnknownKey{
				BaseKey: jwk.BaseKey{
					KeyID: "C",
				},
				KeyType: jwk.KeyTypeOctet,
			},
		}
		ids := make([]string, len(data))
		for i, k := range data {
			ids[i] = k.Kid()
		}
		sort.Strings(ids)
		jwk.SortKey(data)
		for i, v := range ids {
			if data[i].Kid() != v {
				t.Fatalf("must be data[%d] == '%s'", i, v)
			}
		}
	})
	t.Run("name is same, but different type", func(t *testing.T) {
		data := []jwk.Key{
			&jwk.UnknownKey{
				BaseKey: jwk.BaseKey{
					KeyID: "A",
				},
				KeyType: jwk.KeyTypeOctet,
			},
			&jwk.UnknownKey{
				BaseKey: jwk.BaseKey{
					KeyID: "A",
				},
				KeyType: jwk.KeyTypeRSA,
			},
			&jwk.UnknownKey{
				BaseKey: jwk.BaseKey{
					KeyID: "A",
				},
				KeyType: jwk.KeyTypeEC,
			},
		}
		jwk.SortKey(data)
		if data[0].Kty() != jwk.KeyTypeEC {
			t.Fatalf("must be data[%d].Kty() == '%s'", 0, jwk.KeyTypeEC)
		}
		if data[1].Kty() != jwk.KeyTypeRSA {
			t.Fatalf("must be data[%d].Kty() == '%s'", 1, jwk.KeyTypeRSA)
		}
		if data[2].Kty() != jwk.KeyTypeOctet {
			t.Fatalf("must be data[%d].Kty() == '%s'", 2, jwk.KeyTypeOctet)
		}
	})
	t.Run("name and type mixed", func(t *testing.T) {
		// A(oct), B(oct), C(EC), C(oct), D(oct), E(EC), E(RSA), E(oct)
		data := []jwk.Key{
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "E"}, KeyType: jwk.KeyTypeEC},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "C"}, KeyType: jwk.KeyTypeOctet},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "E"}, KeyType: jwk.KeyTypeRSA},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "D"}, KeyType: jwk.KeyTypeOctet},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "B"}, KeyType: jwk.KeyTypeOctet},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "C"}, KeyType: jwk.KeyTypeEC},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "A"}, KeyType: jwk.KeyTypeOctet},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "E"}, KeyType: jwk.KeyTypeOctet},
		}
		expected := []jwk.Key{
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "A"}, KeyType: jwk.KeyTypeOctet},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "B"}, KeyType: jwk.KeyTypeOctet},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "C"}, KeyType: jwk.KeyTypeEC},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "C"}, KeyType: jwk.KeyTypeOctet},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "D"}, KeyType: jwk.KeyTypeOctet},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "E"}, KeyType: jwk.KeyTypeEC},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "E"}, KeyType: jwk.KeyTypeRSA},
			&jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: "E"}, KeyType: jwk.KeyTypeOctet},
		}
		jwk.SortKey(data)
		for i, k := range expected {
			if data[i].Kid() != k.Kid() {
				t.Fatalf("data[%d] must be kid = '%s'", i, k.Kid())
			}
			if data[i].Kty() != k.Kty() {
				t.Fatalf("data[%d] must be kty = '%s'", i, k.Kty())
			}
		}
	})
	t.Run("random generated 1M, mixed test", func(t *testing.T) {
		const GENERATED_LENGTH = 1_000_000
		const ID_MINLEN = 3
		const ID_MAXLEN = 4
		var TYPE_ONEOF = []jwk.KeyType{jwk.KeyTypeOctet, jwk.KeyTypeEC, jwk.KeyTypeRSA}
		var KTY_TO_INT_TABLE = map[jwk.KeyType]int{
			jwk.KeyTypeEC:    0,
			jwk.KeyTypeRSA:   1,
			jwk.KeyTypeOctet: 2,
		}
		var CHARSET = []rune("abcdefghijklmnopqrstuvwxyz")
		gen_id := func(length int) string {
			result := make([]rune, 0, length)
			for i := 0; i < length; i++ {
				result = append(result, CHARSET[rand.Intn(len(CHARSET))])
			}
			return string(result)
		}

		keys := make([]jwk.Key, 0, GENERATED_LENGTH)
		ids := make([]string, 0, GENERATED_LENGTH)
		for i := 0; i < GENERATED_LENGTH; i++ {
			kid := gen_id(ID_MINLEN + rand.Intn((ID_MAXLEN-ID_MINLEN)+1))
			kty := TYPE_ONEOF[rand.Intn(len(TYPE_ONEOF))]
			keys = append(keys, &jwk.UnknownKey{BaseKey: jwk.BaseKey{KeyID: kid}, KeyType: kty})
			ids = append(ids, kid)
		}
		sort.Strings(ids)
		jwk.SortKey(keys)
		for i := 0; i < GENERATED_LENGTH; i++ {
			if ids[i] != keys[i].Kid() {
				t.Fatalf("expected data[%d].Kid() is '%s', but got '%s'", i, ids[i], keys[i].Kty())
			}
			currID := keys[i].Kid()
			currTYP := KTY_TO_INT_TABLE[keys[i].Kty()]
			for j := i; j < GENERATED_LENGTH && keys[j].Kid() == currID; j++ {
				jTYP := KTY_TO_INT_TABLE[keys[j].Kty()]
				if currTYP > jTYP {
					t.Fatalf("from data[%d] to data[%d], data[%d].Kty() is '%s', but data[%d].Kty() is '%s'", i, j, i, keys[i].Kty(), j, keys[j].Kty())
				}
				if jTYP > currTYP {
					currTYP = jTYP
				}
			}
		}

	})
}
