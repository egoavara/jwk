package jwk

type KeyOps map[KeyOp]struct{}

type KeyOp string

// https://datatracker.ietf.org/doc/html/rfc7517#section-8.3.2
const (
	KeyOpSign       KeyOp = "sign"       // Compute digital signature or MAC
	KeyOpVerify     KeyOp = "verify"     // Verify digital signature or MAC
	KeyOpEncrypt    KeyOp = "encrypt"    // Encrypt content
	KeyOpDecrypt    KeyOp = "decrypt"    // Decrypt content and validate decryption, if applicable
	KeyOpWrapKey    KeyOp = "wrapKey"    // Encrypt key
	KeyOpUnwrapKey  KeyOp = "unwrapKey"  // Decrypt key and validate decryption, if applicable
	KeyOpDeriveKey  KeyOp = "deriveKey"  // Derive key
	KeyOpDeriveBits KeyOp = "deriveBits" // Derive bits not to be used as a key
)

func NewKeyOpsFromStr(ops ...string) KeyOps {
	m := make(map[KeyOp]struct{})
	for _, op := range ops {
		m[KeyOp(op)] = struct{}{}
	}
	return KeyOps(m)
}

func (m KeyOps) In(op KeyOp) bool {
	_, ok := m[op]
	return ok
}

func (m KeyOps) All(ops ...KeyOp) bool {
	for _, op := range ops {
		if _, ok := m[op]; !ok {
			return false
		}
	}
	return true
}

func (m KeyOps) Any(ops ...KeyOp) bool {
	for _, op := range ops {
		if _, ok := m[op]; ok {
			return true
		}
	}
	return false
}
