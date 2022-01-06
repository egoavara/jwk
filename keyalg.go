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

var _ALG_TABLE = map[Algorithm]KeyType{
	AlgorithmHS256:         KeyTypeOctet,
	AlgorithmHS384:         KeyTypeOctet,
	AlgorithmHS512:         KeyTypeOctet,
	AlgorithmRS256:         KeyTypeRSA,
	AlgorithmRS384:         KeyTypeRSA,
	AlgorithmRS512:         KeyTypeRSA,
	AlgorithmES256:         KeyTypeEC,
	AlgorithmES384:         KeyTypeEC,
	AlgorithmES512:         KeyTypeEC,
	AlgorithmPS256:         KeyTypeRSA,
	AlgorithmPS384:         KeyTypeRSA,
	AlgorithmPS512:         KeyTypeRSA,
	AlgorithmRSA1_5:        KeyTypeRSA,
	AlgorithmRSAOAEP:       KeyTypeRSA,
	AlgorithmRSAOAEP256:    KeyTypeRSA,
	AlgorithmA128KW:        KeyTypeOctet,
	AlgorithmA192KW:        KeyTypeOctet,
	AlgorithmA256KW:        KeyTypeOctet,
	AlgorithmECDHES:        KeyTypeEC,
	AlgorithmECDHES_A128KW: KeyTypeEC,
	AlgorithmECDHES_A192KW: KeyTypeEC,
	AlgorithmECDHES_A256KW: KeyTypeEC,
	AlgorithmA128GCMKW:     KeyTypeOctet,
	AlgorithmA192GCMKW:     KeyTypeOctet,
	AlgorithmA256GCMKW:     KeyTypeOctet,
	AlgorithmNone:          "",
	// TODO : what is that?
	// AlgorithmDir
	// AlgorithmPBES2_HS256_A128KW
	// AlgorithmPBES2_HS384_A192KW
	// AlgorithmPBES2_HS512_A256KW
	// AlgorithmA128CBC_HS256
	// AlgorithmA192CBC_HS384
	// AlgorithmA256CBC_HS512
	// AlgorithmA128GCM
	// AlgorithmA192GCM
	// AlgorithmA256GCM
}

func (alg Algorithm) IsKnown() bool {
	_, ok := _ALG_TABLE[alg]
	return ok
}
func (alg Algorithm) Exist() bool {
	return len(alg) > 0
}

func (alg Algorithm) IntoKeyType() KeyType {
	return _ALG_TABLE[alg]
}
