package jwk

import (
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

type (
	OptionalJWTVerifier interface {
		WithJWTVerifier(*OptionJWTVerifier)
	}
	fnOptionalJWTVerifier func(*OptionJWTVerifier)
	OptionJWTVerifier     struct {
		WithoutGuessKey bool
		IgnoreJOSEJWS   bool
		IgnoreJOSEJWK   bool
	}
	JWTVerifier interface {
		Keyfunc(*jwt.Token) (interface{}, error)
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
	// JWTVerifierFromToken is using JOSE Header like `jku`, `jwk`
	JWTVerifierFromToken struct {
		OptionJWTVerifier
	}
)

var ErrNoKeyForVerifier = errors.New("no key for verifier")
var (
	signingMethodTable = map[Algorithm]jwt.SigningMethod{
		AlgorithmRS256: jwt.SigningMethodRS256,
		AlgorithmRS384: jwt.SigningMethodRS384,
		AlgorithmRS512: jwt.SigningMethodRS512,

		AlgorithmES256: jwt.SigningMethodES256,
		AlgorithmES384: jwt.SigningMethodES384,
		AlgorithmES512: jwt.SigningMethodES512,

		AlgorithmHS256: jwt.SigningMethodHS256,
		AlgorithmHS384: jwt.SigningMethodHS384,
		AlgorithmHS512: jwt.SigningMethodHS512,

		AlgorithmPS256: jwt.SigningMethodPS256,
		AlgorithmPS384: jwt.SigningMethodPS384,
		AlgorithmPS512: jwt.SigningMethodPS512,

		AlgorithmNone: jwt.SigningMethodNone,
	}
)

// var jwtSigningMethod = map[Algorithm]jwt.SigningMethod{

// }

func (fn fnOptionalJWTVerifier) WithJWTVerifier(opt *OptionJWTVerifier) {
	fn(opt)
}

func WithGuess(guess bool) OptionalJWTVerifier {
	return fnOptionalJWTVerifier(func(oj *OptionJWTVerifier) { oj.WithoutGuessKey = !guess })
}

// source can be one of `*Set`, `Key`, `*Fetcher`, `<nil>`
// It can be nil return, if source is unknown type or <nil>
// when source is <nil>, it return JWTVerifierFromToken
func LetKeyfunc(source interface{}, options ...OptionalJWTVerifier) jwt.Keyfunc {
	if ver := NewJWTVerifier(source); ver != nil {
		return ver.Keyfunc
	}
	return nil
}
func LetSigningMethod(key Key) jwt.SigningMethod {
	return signingMethodTable[GuessAlgorithm(key)]
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
func (ver *JWTVerifierFromFetcher) Keyfunc(tk *jwt.Token) (interface{}, error) {
	set, err := ver.Fetcher.Get()
	if err != nil {
		return nil, err
	}
	var k Key
	if !ver.WithoutGuessKey {
		k = keyguess(set, tk)
	} else {
		k = set.GetUniqueKey(tk.Header["kid"].(string), Algorithm(tk.Header["alg"].(string)).IntoKeyType())
	}
	if k != nil {
		if itf := k.IntoPublicKey(); itf != nil {
			return itf, nil
		} else {
			// TODO : More detailed error
			return nil, ErrNoKeyForVerifier
		}
	}
	return nil, ErrNoKeyForVerifier
}
func (ver *JWTVerifierFromKey) Keyfunc(tk *jwt.Token) (interface{}, error) {
	if isValidKeyForToken(ver.Key, tk) {
		if itf := ver.Key.IntoPublicKey(); itf != nil {
			return itf, nil
		} else {
			// TODO : More detailed error
			return nil, ErrNoKeyForVerifier
		}
	}
	return nil, ErrNoKeyForVerifier
}
func (ver *JWTVerifierFromSet) Keyfunc(tk *jwt.Token) (interface{}, error) {
	var k Key
	if !ver.WithoutGuessKey {
		k = keyguess(ver.Set, tk)
	} else {
		k = ver.Set.GetUniqueKey(tk.Header["kid"].(string), Algorithm(tk.Header["alg"].(string)).IntoKeyType())
	}
	if k != nil {
		if itf := k.IntoPublicKey(); itf != nil {
			return itf, nil
		} else {
			// TODO : More detailed error
			return nil, ErrNoKeyForVerifier
		}
	}
	return nil, ErrNoKeyForVerifier
}

func keyguess(set *Set, token *jwt.Token) Key {
	if kid, ok := token.Header["kid"]; ok {
		skid, ok := kid.(string)
		if !ok {
			// TODO : kid must be string
			return nil
		}
		keys := set.GetKeys(skid)
		switch len(keys) {
		case 0:
		case 1:
			if isValidKeyForToken(keys[0], token) {
				return keys[0]
			}
		default:
			for _, k := range keys {
				if isValidKeyForToken(k, token) {
					return k
				}
			}
		}
		return nil
	}
	return nil
}
func isValidKeyForToken(key Key, token *jwt.Token) bool {
	// alg field must be exist
	if dat, ok := token.Header["alg"].(string); ok {
		return IsCompatibleKey(key, Algorithm(dat))
	} else {
		// TODO : alg must be string but got other type
		return false
	}
}
