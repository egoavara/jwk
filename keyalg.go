package jwk

type Algorithm string

// https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1.2
const (
	// Optional, No digital signature or MAC performed
	AlgorithmNone Algorithm = "none"
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
)

func (alg Algorithm) Exist() bool {
	return len(alg) > 0
}
