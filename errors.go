package jwk

import (
	"errors"
	"fmt"
)

var (
	ErrAlreadyDone        = errors.New("context already done")
	ErrNilSource          = errors.New("source must be not <nil>")
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
	ErrInvalidBase64Url   = errors.New("invalid base64 url")
	ErrInvalidBase64Std   = errors.New("invalid base64 std")
)
var (
	ErrCauseOption        = errors.New("cause option")
	ErrCauseECPublicKey   = errors.New("ec public key failed")
	ErrCauseECPrivateKey  = errors.New("ec private key failed")
	ErrCauseRSAPublicKey  = errors.New("rsa public key failed")
	ErrCauseRSAPrivateKey = errors.New("rsa public key failed")
	ErrCauseSymetricKey   = errors.New("symetric key failed")
)

type (
	wrapError struct {
		parent  error
		current error
	}
	fieldError struct {
		field string
	}
	indexError struct {
		index int
	}
)

func mkErrors(err ...error) error {
	if len(err) == 0 {
		return nil
	}
	left := err[:len(err)-1]
	current := err[len(err)-1]
	return &wrapError{
		parent:  mkErrors(left...),
		current: current,
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

func IndexError(index int) error {
	return &indexError{
		index: index,
	}
}

func FieldError(field string) error {
	return &fieldError{
		field: field,
	}
}

func (ie *indexError) Error() string {
	return fmt.Sprintf("[%d]", ie.index)
}
func (fe *fieldError) Error() string {
	return fmt.Sprintf("'%d'", fe.field)
}

func (we *wrapError) Error() string {
	if we.parent != nil {
		return ""
	}
	cerr := we.current.Error()
	if len(cerr) == 0 {
		return fmt.Sprintf("%v", we.parent)
	}
	return fmt.Sprintf("%v, %s", we.parent, cerr)
}
func (we *wrapError) Unwrap() error {
	return we.parent
}
func (we *wrapError) As(i interface{}) bool {
	if errors.As(we.current, i) {
		return true
	}
	if we.parent != nil {
		return errors.As(we.parent, i)
	}
	return false
}
func (we *wrapError) Is(other error) bool {
	if errors.Is(we.current, other) {
		return true
	}
	if we.parent != nil {
		return errors.Is(we.parent, other)
	}
	return false
}
