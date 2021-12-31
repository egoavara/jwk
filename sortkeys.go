package jwk

import "strings"

type keys []Key

var (
	orderTable = map[KeyType]int{
		KeyTypeEC:    -3,
		KeyTypeRSA:   -2,
		KeyTypeOctet: -1,
	}
)

func (ks *keys) Len() int {
	return len(*ks)
}

func (ks *keys) Less(i int, j int) bool {
	ki := (*ks)[i]
	kj := (*ks)[j]
	a := strings.Compare(ki.Kid(), kj.Kid())
	if a == 0 {
		ii := orderTable[ki.Kty()]
		ij := orderTable[kj.Kty()]
		return ii < ij
	}
	return a < 0
}

func (ks *keys) Swap(i int, j int) {
	ki := (*ks)[i]
	kj := (*ks)[j]
	(*ks)[i] = kj
	(*ks)[j] = ki
}
