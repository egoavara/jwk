package jwk

type KeyType string

// https://www.rfc-editor.org/rfc/rfc7518.html#section-7.4.2
const (
	// Recommanded +, Elliptic Curve
	KeyTypeEC KeyType = "EC"
	// Required, RSA
	KeyTypeRSA KeyType = "RSA"
	// Required, Octet Sequence
	KeyTypeOctet KeyType = "oct"
)
