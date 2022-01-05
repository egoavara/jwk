package jwk

import (
	"sort"
	"strings"
)

func SortKey(keys []Key) {
	tmp := keySortingHelper(keys)
	sort.Sort(&tmp)
}

type keySortingHelper []Key

var (
	orderTable = map[KeyType]int{
		KeyTypeEC:    -3,
		KeyTypeRSA:   -2,
		KeyTypeOctet: -1,
	}
)

func (ks *keySortingHelper) Len() int {
	return len(*ks)
}

func (ks *keySortingHelper) Less(i int, j int) bool {
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

func (ks *keySortingHelper) Swap(i int, j int) {
	ki := (*ks)[i]
	kj := (*ks)[j]
	(*ks)[i] = kj
	(*ks)[j] = ki
}
