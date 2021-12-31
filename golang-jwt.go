package jwk

import "github.com/golang-jwt/jwt/v4"

type (
	OptionalJWTVerifier interface {
		WithJWTVerifier(*OptionJWTVerifier)
	}
	fnOptionalJWTVerifier func(*OptionJWTVerifier)
	OptionJWTVerifier     struct {
		GuessKey bool
	}
	JWTVerifier interface {
		Keyfunc() jwt.Keyfunc
	}
	JWTVerifierFromFetcher struct {
		OptionJWTVerifier
		Fetcher *Fetcher
	}
	JWTVerifierFromSet struct {
		OptionJWTVerifier
		Set *Set
	}
	JWTVerifierFromKey struct {
		OptionJWTVerifier
		Key Key
	}
	JWTVerifierFromToken struct {
		OptionJWTVerifier
		Key Key
	}
)

func (fn fnOptionalJWTVerifier) WithJWTVerifier(opt *OptionJWTVerifier) {
	fn(opt)
}

func WithGuess(guess bool) OptionalJWTVerifier {
	return fnOptionalJWTVerifier(func(oj *OptionJWTVerifier) { oj.GuessKey = guess })
}

// source can be one of `*Set`, `Key`
// It can be nil return, if source is unknown type or <nil>
func LetJWT(source interface{}, options ...OptionalJWTVerifier) jwt.Keyfunc {
	if ver := NewJWTVerifier(source); ver != nil {
		return ver.Keyfunc()
	}
	return nil
}

func NewJWTVerifier(source interface{}, options ...OptionalJWTVerifier) JWTVerifier {
	switch src := source.(type) {
	case *Set:
		return NewJWTVerifierFromSet(src, options...)
	case *Fetcher:
		return NewJWTVerifierFromFetcher(src, options...)
	case Key:
		return NewJWTVerifierFromKey(src, options...)
	default:
		return nil
	}
}

func NewJWTVerifierFromSet(set *Set, options ...OptionalJWTVerifier) *JWTVerifierFromSet {
	v := &JWTVerifierFromSet{
		Set: set,
	}
	for _, oj := range options {
		oj.WithJWTVerifier(&v.OptionJWTVerifier)
	}
	return v
}

func NewJWTVerifierFromKey(key Key, options ...OptionalJWTVerifier) *JWTVerifierFromKey {
	v := &JWTVerifierFromKey{
		Key: key,
	}
	for _, oj := range options {
		oj.WithJWTVerifier(&v.OptionJWTVerifier)
	}
	return v
}

func NewJWTVerifierFromFetcher(fetcher *Fetcher, options ...OptionalJWTVerifier) *JWTVerifierFromFetcher {
	v := &JWTVerifierFromFetcher{
		Fetcher: fetcher,
	}
	for _, oj := range options {
		oj.WithJWTVerifier(&v.OptionJWTVerifier)
	}
	return v
}
func (ver *JWTVerifierFromFetcher) Keyfunc() jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		key, err := ver.Fetcher.Maybe()
		if err != nil {
			return nil, err
		}
		t.Header

	}
}
func (ver *JWTVerifierFromKey) Keyfunc() jwt.Keyfunc {

}
func (ver *JWTVerifierFromSet) Keyfunc() jwt.Keyfunc {

}
