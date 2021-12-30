package jwk

import (
	"errors"
	"fmt"
)

type (
	ErrorIndex struct {
		Cause  error
		Index  int
		Detail error
	}
	ErrorDetail struct {
		Cause  error
		Detail error
	}
	ErrorField struct {
		Cause  error
		Field  string
		Detail error
	}
)

var (
	ErrX509Certificate = errors.New("x509 certificate failed")
	ErrInvalidContext  = errors.New("invalid context")
	ErrInvalidURL      = errors.New("invalid url")
	ErrRefresh         = errors.New("refresh failed")
	ErrHTTPRequest     = errors.New("http request failed")
	ErrContextDone     = errors.New("context done")
	ErrJSON            = errors.New("json error")
	ErrSetInnerKey     = errors.New("set inner key failed")
	ErrKeyNoRequired   = errors.New("no `kty`")
	ErrKeyParse        = errors.New("error while parsing")
	ErrKeyPubECFailed  = errors.New("ec public key failed")
	ErrKeyPriECFailed  = errors.New("ec private key failed")
	ErrKeyPubRSAFailed = errors.New("rsa public key failed")
	ErrKeyPriRSAFailed = errors.New("rsa private key failed")
	ErrKeyUnknownField = errors.New("unknown field")
)

func errorCause(cause error, defailFormat string, params ...interface{}) error {
	return &ErrorDetail{
		Cause:  cause,
		Detail: fmt.Errorf(defailFormat, params...),
	}
}
func errorCauseFieldFrom(cause error, field string, err error) error {
	return &ErrorField{
		Cause:  cause,
		Field:  field,
		Detail: err,
	}
}

func errorCauseField(cause error, field string, defailFormat string, params ...interface{}) error {
	return &ErrorField{
		Cause:  cause,
		Field:  field,
		Detail: fmt.Errorf(defailFormat, params...),
	}
}

func errorCauseAtFrom(cause error, at int, err error) error {
	return &ErrorIndex{
		Cause:  cause,
		Index:  at,
		Detail: err,
	}
}
func errorCauseAt(cause error, at int, defailFormat string, params ...interface{}) error {
	return &ErrorIndex{
		Cause:  cause,
		Index:  at,
		Detail: fmt.Errorf(defailFormat, params...),
	}
}
func (e *ErrorDetail) Error() string {
	return fmt.Sprintf("JWK Fail : %v : %v", e.Cause, e.Detail)
}

func (e *ErrorDetail) Unwrap() error {
	return e.Cause
}

func (e *ErrorField) Error() string {
	return fmt.Sprintf("JWK Fail : %v : field = '%s' : %v", e.Cause, e.Field, e.Detail)
}

func (e *ErrorField) Unwrap() error {
	return e.Cause
}

func (e *ErrorIndex) Error() string {
	return fmt.Sprintf("JWK Fail : %v : [%d] : %v", e.Cause, e.Index, e.Detail)
}

func (e *ErrorIndex) Unwrap() error {
	return e.Cause
}
