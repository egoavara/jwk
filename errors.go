package jwk

import (
	"errors"
	"fmt"
)

type (
	errWrapIndex struct {
		Index  int
		Origin error
	}
	errWrapDetail struct {
		Origin error
		Detail string
	}
	errWrapField struct {
		Origin error
		Field  string
	}
)

var (
	ErrAlreadyDone  = errors.New("context already done")
	ErrX509         = errors.New("x509 failed")
	ErrBase64       = errors.New("base64 failed")
	ErrInvalidURL   = errors.New("invalid url")
	ErrInvalidJSON  = errors.New("invalid json")
	ErrHTTPRequest  = errors.New("http request failed")
	ErrNotFoundKey  = errors.New("not found key")
	ErrRequirement  = errors.New("not satisfied requirement")
	ErrPubECFailed  = errors.New("ec public key failed")
	ErrPriECFailed  = errors.New("ec private key failed")
	ErrPubRSAFailed = errors.New("rsa public key failed")
	ErrPriRSAFailed = errors.New("rsa private key failed")
	ErrUnknownField = errors.New("unknown field")
)

func wrapDetail(cause error, detail error) error {
	return &errWrapDetail{
		Origin: cause,
		Detail: detail.Error(),
	}
}
func wrapDetailf(cause error, format string, args ...interface{}) error {

	return &errWrapDetail{
		Origin: cause,
		Detail: fmt.Sprintf(format, args...),
	}
}
func wrapField(cause error, field string) error {
	return &errWrapField{
		Origin: cause,
		Field:  field,
	}
}
func wrapIndex(cause error, index int) error {
	return &errWrapIndex{
		Origin: cause,
		Index:  index,
	}
}

func (e *errWrapDetail) Error() string {
	return fmt.Sprintf("%v cause '%v'", e.Origin, e.Detail)
}

func (e *errWrapDetail) Unwrap() error {
	return e.Origin
}

func (e *errWrapField) Error() string {
	return fmt.Sprintf("%v in %v", e.Origin, e.Field)
}

func (e *errWrapField) Unwrap() error {
	return e.Origin
}

func (e *errWrapIndex) Error() string {
	return fmt.Sprintf("%v at %v", e.Origin, e.Index)
}

func (e *errWrapIndex) Unwrap() error {
	return e.Origin
}
