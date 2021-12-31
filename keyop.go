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
func (ops KeyOps) IsValidCombination() bool {
	if len(ops) > 2 {
		return false
	}
	if len(ops) <= 1 {
		return true
	}
	if _, ok := ops[KeyOpSign]; ok {
		if _, ok := ops[KeyOpVerify]; ok {
			return true
		}
	}
	if _, ok := ops[KeyOpEncrypt]; ok {
		if _, ok := ops[KeyOpDecrypt]; ok {
			return true
		}
	}
	if _, ok := ops[KeyOpWrapKey]; ok {
		if _, ok := ops[KeyOpUnwrapKey]; ok {
			return true
		}
	}
	return false
}
func (ops KeyOps) Compatible(use KeyUse) bool {
	// TODO : Is that right?
	var trg KeyOp
	switch use {
	case KeyUseEnc:
		trg = KeyOpUnwrapKey
	case KeyUseSig:
		trg = KeyOpVerify
	}
	_, ok := ops[trg]
	return ok
}
func (ops KeyOps) AsSlice() []KeyOp {
	slc := make([]KeyOp, 0, len(ops))
	for k := range ops {
		slc = append(slc, k)
	}
	return slc
}

func (op KeyOp) IsKnown() bool {
	switch op {
	case KeyOpSign:
		fallthrough
	case KeyOpVerify:
		fallthrough
	case KeyOpEncrypt:
		fallthrough
	case KeyOpDecrypt:
		fallthrough
	case KeyOpWrapKey:
		fallthrough
	case KeyOpUnwrapKey:
		fallthrough
	case KeyOpDeriveKey:
		fallthrough
	case KeyOpDeriveBits:
		return true
	default:
		return false
	}
}
