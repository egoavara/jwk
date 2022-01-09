package jwk

import "crypto/ecdsa"

var (
	ecBitSizeToAlg = map[int]Algorithm{
		256: AlgorithmES256,
		384: AlgorithmES384,
		521: AlgorithmES512,
	}
)

func GuessAlgorithm(key Key) Algorithm {
	if key.Alg().Exist() {
		return key.Alg()
	}
	switch key.Kty() {
	case KeyTypeEC:
		if pubk := key.IntoPublicKey().(*ecdsa.PublicKey); pubk != nil {
			return ecBitSizeToAlg[pubk.Params().BitSize]
		}
	case KeyTypeOctet:
		return ""
	}
	return ""

}

// In RFC, key's `alg` header is optional
// So if there is no defined algorithm, you need to guess it is compatible algorithm
func IsCompatibleKey(key Key, alg Algorithm) bool {
	if len(alg) <= 0 {
		// TODO : panic?
		return false
	}
	if keyalg := key.Alg(); len(keyalg) > 0 {
		return keyalg == alg
	}
	// TODO : key check steps
	// if key.Kty() != alg.IntoKeyType() {
	// 	return false
	// }
	return false
}
