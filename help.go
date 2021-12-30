package jwk

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
)

var reflectStr = reflect.TypeOf("")

func utilURL(rurl interface{}) (*url.URL, error) {
	switch v := rurl.(type) {
	case *string:
		return url.Parse(*v)
	case string:
		return url.Parse(v)
	case url.URL:
		return &v, nil
	case *url.URL:
		return v, nil
	default:
		reflectVal := reflect.ValueOf(v)
		if reflectVal.Type().ConvertibleTo(reflectStr) {
			return utilURL(reflectVal.Convert(reflectStr).Interface())
		}
		return nil, fmt.Errorf("unsupported url type %T", v)
	}
}
func utilResponse(rurl *url.URL, ctx context.Context, clt *http.Client) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rurl.String(), nil)
	if err != nil {
		return nil, err
	}
	return clt.Do(req)
}

func utilInterfaceOr(i interface{}, vdefault interface{}) interface{} {
	if i == nil {
		return vdefault
	}
	return i
}

var (
	errKeyNotExist = errors.New("key not exist")
	errInvalidType = errors.New("unvalid type")
)

func utilConsumeURL(m map[string]interface{}, k string) (*url.URL, error) {
	surl, err := utilConsumeStr(m, k)
	if err != nil {
		return nil, err
	}
	return url.Parse(surl)
}

func utilConsumeStr(m map[string]interface{}, k string) (string, error) {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			delete(m, k)
			return s, nil
		}
		return "", errInvalidType
	}
	return "", errKeyNotExist
}
func utilConsumeArrStr(m map[string]interface{}, k string) ([]string, error) {
	if v, ok := m[k]; ok {
		if s, ok := v.([]interface{}); ok {
			delete(m, k)
			res := make([]string, len(s))
			for i, is := range s {
				res[i] = is.(string)
			}
			return res, nil
		}
		return nil, errInvalidType
	}
	return nil, errKeyNotExist
}
func utilConsumeArrMap(m map[string]interface{}, k string) ([]map[string]interface{}, error) {
	if v, ok := m[k]; ok {
		if s, ok := v.([]interface{}); ok {
			delete(m, k)
			res := make([]map[string]interface{}, len(s))
			for i, is := range s {
				res[i] = is.(map[string]interface{})
			}
			return res, nil
		}
		return nil, errInvalidType
	}
	return nil, errKeyNotExist
}
func utilConsumeMap(m map[string]interface{}, k string) (map[string]interface{}, error) {
	if v, ok := m[k]; ok {
		if s, ok := v.(map[string]interface{}); ok {
			delete(m, k)
			return s, nil
		}
		return nil, errInvalidType
	}
	return nil, errKeyNotExist
}

func utilConsumeB64url(m map[string]interface{}, k string) ([]byte, error) {
	if s, err := utilConsumeStr(m, k); err == nil {

		bts, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		return bts, nil
	} else {
		return nil, err
	}
}

func utilConsumeB64std(m map[string]interface{}, k string) ([]byte, error) {
	if s, err := utilConsumeStr(m, k); err == nil {
		bts, err := base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		return bts, nil
	} else {
		return nil, err
	}
}
