package jwk

import (
	"errors"
	"fmt"
)

var (
	ErrContextDone        = errors.New("context already done")
	ErrNil                = errors.New("not nil")
	ErrParameter          = errors.New("parameter")
	ErrRequirement        = errors.New("not satisfied requirement")
	ErrHTTPRequest        = errors.New("http request failed")
	ErrNotExist           = errors.New("not exist")
	ErrInnerKey           = errors.New("inner key failed")
	ErrInvalidString      = errors.New("invalid string")
	ErrInvalidArrayString = errors.New("invalid []string")
	ErrInvalidArrayObject = errors.New("invalid []object")
	ErrInvalidObject      = errors.New("invalid object")
	ErrInvalidURL         = errors.New("invalid url")
	ErrInvalidX509        = errors.New("invalid x509")
	ErrInvalidJSON        = errors.New("invalid json")
	ErrInvalidBase64      = errors.New("invalid base64")
	ErrUnknownKeyUse      = errors.New("unknown use")
)
var (
	ErrCauseOption        = errors.New("cause option")
	ErrCauseUnknown       = errors.New("unknown")
	ErrCauseECPublicKey   = errors.New("ec public key failed")
	ErrCauseECPrivateKey  = errors.New("ec private key failed")
	ErrCauseRSAPublicKey  = errors.New("rsa public key failed")
	ErrCauseRSAPrivateKey = errors.New("rsa private key failed")
	ErrCauseRSAValidate   = errors.New("rsa validate fail")
	ErrCauseSymetricKey   = errors.New("symetric key failed")
)
var (
	ErrECInvalidBytesLength     = errors.New("invalid byte length")
	ErrNoSelectedKey            = errors.New("no selected key")
	ErrNotExpectedKty           = errors.New("not expected kty")
	ErrNotCompatible            = errors.New("not compatible")
	ErrSHA1Size                 = errors.New("sha1 size")
	ErrSHA256Size               = errors.New("sha256 size")
	ErrInvalidCombination       = errors.New("invalid combination")
	ErrDisallowBothUseKeyops    = errors.New("disallow both use and key_ops")
	ErrDisallowUnkwownField     = errors.New("disallow unknown field")
	ErrDisallowUnknownOp        = errors.New("disallow unknown op")
	ErrDisallowUnknownAlgorithm = errors.New("disallow unknown algorithm")
	ErrDisallowDuplicatedOps    = errors.New("disallow duplicated ops")
)

type (
	wrapError struct {
		current error
		child   error
	}
	FieldError string
	IndexError int
)

func makeErrors(err ...error) error {
	if len(err) == 0 {
		return nil
	}
	return &wrapError{
		current: err[0],
		child:   makeErrors(err[1:]...),
	}
}
func replaceErrors(err error, from error, to error) {
	for ; errors.Is(err, from); err = errors.Unwrap(err) {
		if k, ok := err.(*wrapError); ok {
			if errors.Is(k.current, from) {
				k.current = to
			}
		}
	}
}

func (ie IndexError) Error() string {
	return fmt.Sprintf("[%d]", int(ie))
}
func (fe FieldError) Error() string {
	return fmt.Sprintf("'%s'", string(fe))
}

func (we *wrapError) Error() string {
	if we.child == nil {
		return fmt.Sprintf("%v", we.current)
	}
	return fmt.Sprintf("%v, %v", we.current, we.child)
}

func (we *wrapError) Unwrap() error {
	return we.child
}

func (we *wrapError) As(i interface{}) bool {
	return errors.As(we.current, i)
}

func (we *wrapError) Is(other error) bool {
	return we == other || errors.Is(we.current, other)
}

func (fe *FieldError) Is(other error) bool {
	switch oth := other.(type) {
	case FieldError:
		return *fe == oth
	case *FieldError:
		return *fe == *oth
	}
	return false
}

func (ie *IndexError) Is(other error) bool {
	switch oth := other.(type) {
	case IndexError:
		return *ie == oth
	case *IndexError:
		return *ie == *oth
	}
	return false
}
