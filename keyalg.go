package jwk

type Algorithm string

// https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1.2
const (
	// Optional, HMAC using SHA-256
	AlgorithmHS256 Algorithm = "HS256"
	// Optional, HMAC using SHA-384
	AlgorithmHS384 Algorithm = "HS384"
	// Optional, HMAC using SHA-512
	AlgorithmHS512 Algorithm = "HS512"
	// Recommended, RSASSA-PKCS1-v1_5 using SHA-256
	AlgorithmRS256 Algorithm = "RS256"
	// Recommended, RSASSA-PKCS1-v1_5 using SHA-384
	AlgorithmRS384 Algorithm = "RS384"
	// Recommended, RSASSA-PKCS1-v1_5 using SHA-512
	AlgorithmRS512 Algorithm = "RS512"
	// Recommended+, ECDSA using P-256 and SHA-256
	AlgorithmES256 Algorithm = "ES256"
	// Recommended+, ECDSA using P-384 and SHA-384
	AlgorithmES384 Algorithm = "ES384"
	// Recommended+, ECDSA using P-512 and SHA-512
	AlgorithmES512 Algorithm = "ES512"
	// Optional, RSASSA-PSS using SHA-256 and MGF1 with SHA-256
	AlgorithmPS256 Algorithm = "PS256"
	// Optional, RSASSA-PSS using SHA-384 and MGF1 with SHA-384
	AlgorithmPS384 Algorithm = "PS384"
	// Optional, RSASSA-PSS using SHA-512 and MGF1 with SHA-512
	AlgorithmPS512 Algorithm = "PS512"
	// Optional, No digital signature or MAC performed
	AlgorithmNone Algorithm = "none"
	// Recommended-, RSAES-PKCS1-v1_5
	AlgorithmRSA1_5 Algorithm = "RSA1_5"
	//Recommended+, RSAES OAEP using default parameters
	AlgorithmRSAOAEP Algorithm = "RSA-OAEP"
	//Optional, RSAES OAEP using SHA-256 and MGF1 with
	AlgorithmRSAOAEP256 Algorithm = "RSA-OAEP-256"
	//Recommended, AES Key Wrap using 128-bit key
	AlgorithmA128KW Algorithm = "A128KW"
	//Optional, AES Key Wrap using 192-bit key
	AlgorithmA192KW Algorithm = "A192KW"
	//Recommended, AES Key Wrap using 256-bit key
	AlgorithmA256KW Algorithm = "A256KW"
	//Recommended, Direct use of a shared symmetric key
	AlgorithmDir Algorithm = "dir"
	// Recommended+, ECDH-ES using Concat KDF
	AlgorithmECDHES Algorithm = "ECDH-ES"
	// Recommended, ECDH-ES using Concat KDF and "A128KW" wrapping
	AlgorithmECDHES_A128KW Algorithm = "ECDH-ES+A128KW"
	// Optional, ECDH-ES using Concat KDF and "A192KW" wrapping
	AlgorithmECDHES_A192KW Algorithm = "ECDH-ES+A192KW"
	// Recommended, ECDH-ES using Concat KDF and "A256KW"wrapping
	AlgorithmECDHES_A256KW Algorithm = "ECDH-ES+A256KW"
	// Optional, Key wrapping with AES GCM using 128-bit key
	AlgorithmA128GCMKW Algorithm = "A128GCMKW"
	// Optional, Key wrapping with AES GCM using 192-bit key
	AlgorithmA192GCMKW Algorithm = "A192GCMKW"
	// Optional, Key wrapping with AES GCM using 256-bit key
	AlgorithmA256GCMKW Algorithm = "A256GCMKW"
	// Optional, PBES2 with HMAC SHA-256 and "A128KW" wrapping
	AlgorithmPBES2_HS256_A128KW Algorithm = "PBES2-HS256+A128KW"
	// Optional, PBES2 with HMAC SHA-384 and "A192KW" wrapping
	AlgorithmPBES2_HS384_A192KW Algorithm = "PBES2-HS384+A192KW"
	// Optional, PBES2 with HMAC SHA-512 and "A256KW" wrapping
	AlgorithmPBES2_HS512_A256KW Algorithm = "PBES2-HS512+A256KW"
	// Required, AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
	AlgorithmA128CBC_HS256 Algorithm = "A128CBC-HS256"
	// Optional, AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
	AlgorithmA192CBC_HS384 Algorithm = "A192CBC-HS384"
	// Required, AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
	AlgorithmA256CBC_HS512 Algorithm = "A256CBC-HS512"
	// Recommended, AES GCM using 128-bit key
	AlgorithmA128GCM Algorithm = "A128GCM"
	// Optional, AES GCM using 192-bit key
	AlgorithmA192GCM Algorithm = "A192GCM"
	// Recommended, AES GCM using 256-bit key
	AlgorithmA256GCM Algorithm = "A256GCM"
)

func (alg Algorithm) IsKnown() bool {
	switch alg {
	case AlgorithmHS256:
		fallthrough
	case AlgorithmHS384:
		fallthrough
	case AlgorithmHS512:
		fallthrough
	case AlgorithmRS256:
		fallthrough
	case AlgorithmRS384:
		fallthrough
	case AlgorithmRS512:
		fallthrough
	case AlgorithmES256:
		fallthrough
	case AlgorithmES384:
		fallthrough
	case AlgorithmES512:
		fallthrough
	case AlgorithmPS256:
		fallthrough
	case AlgorithmPS384:
		fallthrough
	case AlgorithmPS512:
		fallthrough
	case AlgorithmNone:
		fallthrough
	case AlgorithmRSA1_5:
		fallthrough
	case AlgorithmRSAOAEP:
		fallthrough
	case AlgorithmRSAOAEP256:
		fallthrough
	case AlgorithmA128KW:
		fallthrough
	case AlgorithmA192KW:
		fallthrough
	case AlgorithmA256KW:
		fallthrough
	case AlgorithmDir:
		fallthrough
	case AlgorithmECDHES:
		fallthrough
	case AlgorithmECDHES_A128KW:
		fallthrough
	case AlgorithmECDHES_A192KW:
		fallthrough
	case AlgorithmECDHES_A256KW:
		fallthrough
	case AlgorithmA128GCMKW:
		fallthrough
	case AlgorithmA192GCMKW:
		fallthrough
	case AlgorithmA256GCMKW:
		fallthrough
	case AlgorithmPBES2_HS256_A128KW:
		fallthrough
	case AlgorithmPBES2_HS384_A192KW:
		fallthrough
	case AlgorithmPBES2_HS512_A256KW:
		fallthrough
	case AlgorithmA128CBC_HS256:
		fallthrough
	case AlgorithmA192CBC_HS384:
		fallthrough
	case AlgorithmA256CBC_HS512:
		fallthrough
	case AlgorithmA128GCM:
		fallthrough
	case AlgorithmA192GCM:
		fallthrough
	case AlgorithmA256GCM:
		return true
	default:
		return false
	}
}
func (alg Algorithm) Exist() bool {
	return len(alg) > 0
}

func (alg Algorithm) IntoKeyType() KeyType {
	switch alg {
	case AlgorithmHS256:
		return KeyTypeOctet
	case AlgorithmHS384:
		return KeyTypeOctet
	case AlgorithmHS512:
		return KeyTypeOctet
	case AlgorithmRS256:
		return KeyTypeRSA
	case AlgorithmRS384:
		return KeyTypeRSA
	case AlgorithmRS512:
		return KeyTypeRSA
	case AlgorithmES256:
		return KeyTypeEC
	case AlgorithmES384:
		return KeyTypeEC
	case AlgorithmES512:
		return KeyTypeEC
	case AlgorithmPS256:
		return KeyTypeRSA
	case AlgorithmPS384:
		return KeyTypeRSA
	case AlgorithmPS512:
		return KeyTypeRSA
	case AlgorithmRSA1_5:
		return KeyTypeRSA
	case AlgorithmRSAOAEP:
		return KeyTypeRSA
	case AlgorithmRSAOAEP256:
		return KeyTypeRSA
	case AlgorithmA128KW:
		return KeyTypeOctet
	case AlgorithmA192KW:
		return KeyTypeOctet
	case AlgorithmA256KW:
		return KeyTypeOctet
	case AlgorithmECDHES:
		return KeyTypeEC
	case AlgorithmECDHES_A128KW:
		return KeyTypeEC
	case AlgorithmECDHES_A192KW:
		return KeyTypeEC
	case AlgorithmECDHES_A256KW:
		return KeyTypeEC
	case AlgorithmA128GCMKW:
		return KeyTypeOctet
	case AlgorithmA192GCMKW:
		return KeyTypeOctet
	case AlgorithmA256GCMKW:
		return KeyTypeOctet
	case AlgorithmNone:
		// TODO : panics
		panic("TODO : what to do AlgorithmNone?")
	case AlgorithmDir:
		panic("TODO : what is AlgorithmDir?")
	case AlgorithmPBES2_HS256_A128KW:
		panic("TODO : what is AlgorithmPBES2_HS256_A128KW?")
	case AlgorithmPBES2_HS384_A192KW:
		panic("TODO : what is AlgorithmPBES2_HS384_A192KW?")
	case AlgorithmPBES2_HS512_A256KW:
		panic("TODO : what is AlgorithmPBES2_HS512_A256KW?")
	case AlgorithmA128CBC_HS256:
		panic("TODO : what is AlgorithmA128CBC_HS256?")
	case AlgorithmA192CBC_HS384:
		panic("TODO : what is AlgorithmA192CBC_HS384?")
	case AlgorithmA256CBC_HS512:
		panic("TODO : what is AlgorithmA256CBC_HS512?")
	case AlgorithmA128GCM:
		panic("TODO : what is AlgorithmA128GCM?")
	case AlgorithmA192GCM:
		panic("TODO : what is AlgorithmA192GCM?")
	case AlgorithmA256GCM:
		panic("TODO : what is AlgorithmA256GCM?")
	default:
		panic("TODO : what to do?")
	}
}
