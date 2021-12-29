package jwk

type KeyUse string

// https://datatracker.ietf.org/doc/html/rfc7517#section-8.2.2
const (
	KeyUseSig KeyUse = "sig" // Digital Signature or MAC
	KeyUseEnc KeyUse = "enc" // Encryption
)

func (kuse KeyUse) Exist() bool {
	return len(kuse) > 0
}
