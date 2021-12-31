# %%
from Cryptodome.Hash import SHA256, SHA384, SHA512
from Cryptodome.Signature import PKCS1_v1_5, DSS
import base64
import hashlib
import hmac
from Cryptodome.PublicKey import RSA, ECC
# %%


def HS256(password, input):
    return hmac.new(password, input, hashlib.sha256).digest()


def HS384(password, input):
    return hmac.new(password, input, hashlib.sha384).digest()


def HS512(password, input):
    return hmac.new(password, input, hashlib.sha512).digest()


# %%


def RS256Sign(privateKey, input):
    return PKCS1_v1_5.new(privateKey).sign(SHA256.new(input))


def RS256Verify(publicKey, input):
    return PKCS1_v1_5.new(publicKey).verify(SHA256.new(input))


def RS384Sign(privateKey, input):
    return PKCS1_v1_5.new(privateKey).sign(SHA384.new(input))


def RS384Verify(publicKey, input):
    return PKCS1_v1_5.new(publicKey).verify(SHA384.new(input))


def RS512Sign(privateKey, input):
    return PKCS1_v1_5.new(privateKey).sign(SHA512.new(input))


def RS512Verify(publicKey, input):
    return PKCS1_v1_5.new(publicKey).verify(SHA512.new(input))
# %%


def ES256Sign(privateKey, input):
    return DSS.new(privateKey, 'fips-186-3').sign(SHA256.new(input))


def ES256Verify(publicKey, input):
    return DSS.new(publicKey, 'fips-186-3').verify(SHA256.new(input))


# %%
JWSPayload = """{
	"iss":"joe",
	"exp":1300819380,
	"http://example.com/is_root":true
}"""

JWSProtectedHeader = """{
    "typ":"JWT",
    "alg":"HS256"
}"""
Password = b'your-256-bit-secret'


b64JWSProtectedHeader = base64.urlsafe_b64encode(
    bytes(JWSProtectedHeader, encoding='utf8')).replace(b'=', b'')
b64JWSPayload = base64.urlsafe_b64encode(
    bytes(JWSPayload, encoding='utf8')).replace(b'=', b'')
# JWS 사인을 하기 위한 입력값
JWSSigningInput = b64JWSProtectedHeader + b'.' + b64JWSPayload
JWSSignature = base64.urlsafe_b64encode(
    HS256(Password, JWSSigningInput)).replace(b'=', b'')
# 보여주기용 print
print(f'{"BASE64URL(UTF8(JWS Protected Header))":30} : {b64JWSProtectedHeader}')
print(f'{"BASE64URL(UTF8(JWS Payload))":30} : {b64JWSPayload}')
print(f'{"JWSSigningInput":30} : {JWSSigningInput}')
print(f'{"JWSSignature":30} : {JWSSignature}')
# 최종 출력물
print("JWS : ", str(JWSSigningInput + b'.' + JWSSignature, 'ascii'))

# %% RS256
# https://jwt.io/#debugger-io?token=ewogICAgInR5cCI6IkpXVCIsCiAgICAiYWxnIjoiUlMyNTYiCn0.ewoJImlzcyI6ImpvZSIsCgkiZXhwIjoxMzAwODE5MzgwLAoJImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlCn0.CkpTr8irovfQ6CS1Fbg162HkfGqdDNUxuJYSiAusUy6JfxfDUZIyjDMDqKaeChu6A6tOy7o8Ww51Oq5bLYr3Kt3lJpFXqDBDKh5w4YT2iqf7wWuS0ddjGo4iUvPBzTKwuVC_7WSd3EPh61eZCF7oO0e8ILp2wzqNCaA4l_mzV5IeNi08IPIsGYWSuhzggzbNNJlYfzYYNa6qIBfx0BmOc4KRBHdD8r-2kOtTU2HynX4vYoVY7R2vUWoxTuK62yQ2s3oacfAXUKrWYf5pKv6-JJMHUc_tsFQKwS3_injdd9lGIX2JJjmOGSSVh52lAhGyQ7OB_6DDT1psYDsDJ1UGfA&publicKey=-----BEGIN%20PUBLIC%20KEY-----%0AMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo%0A4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0%2FIzW7yWR7QkrmBL7jTKEn5u%0A%2BqKhbwKfBstIs%2BbMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh%0Akd3qqGElvW%2FVDL5AaWTg0nLVkjRo9z%2B40RQzuVaE8AkAFmxZzow3x%2BVJYKdjykkJ%0A0iT9wCS0DRTXu269V264Vf%2F3jvredZiKRkgwlL9xNAwxXFg0x%2FXFw005UWVRIkdg%0AcKWTjpBP2dPwVZ4WWC%2B9aGVd%2BGyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc%0AmwIDAQAB%0A-----END%20PUBLIC%20KEY-----
x509prikey = """-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----"""
prikey = RSA.import_key(x509prikey)

JWSPayload = """{
	"iss":"joe",
	"exp":1300819380,
	"http://example.com/is_root":true
}"""

JWSProtectedHeader = """{
    "typ":"JWT",
    "alg":"RS256"
}"""
Password = b'your-256-bit-secret'

b64JWSProtectedHeader = base64.urlsafe_b64encode(
    bytes(JWSProtectedHeader, encoding='utf8')).replace(b'=', b'')
b64JWSPayload = base64.urlsafe_b64encode(
    bytes(JWSPayload, encoding='utf8')).replace(b'=', b'')
# JWS 사인을 하기 위한 입력값
JWSSigningInput = b64JWSProtectedHeader + b'.' + b64JWSPayload
JWSSignature = base64.urlsafe_b64encode(
    RS256Sign(prikey, JWSSigningInput)).replace(b'=', b'')
# 보여주기용 print
print(f'{"BASE64URL(UTF8(JWS Protected Header))":30} : {b64JWSProtectedHeader}')
print(f'{"BASE64URL(UTF8(JWS Payload))":30} : {b64JWSPayload}')
print(f'{"JWSSigningInput":30} : {JWSSigningInput}')
print(f'{"JWSSignature":30} : {JWSSignature}')
# 최종 출력물
print("JWS : ", str(JWSSigningInput + b'.' + JWSSignature, 'ascii'))

# %% ES256
# https://jwt.io/#debugger-io?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.sugoJkKIlb6fL2L5XQGvghrCm9AxOkstUHZ7zW0HsOfhNZt6U1WAQNLyWqg8MygVKeuz0H0HGhAFNZTshNyuRg&publicKey=-----BEGIN%20PUBLIC%20KEY-----%0AMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs%2Fo5%2BuQbTjL3chynL4wXgUg2R9%0Aq9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B%2BdFabmdT9POxg%3D%3D%0A-----END%20PUBLIC%20KEY-----
# x509 PKCS#8 형식의 ECDSA를 위한 개인키
x509prikey = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----"""
# 개인키를 pycryptodome에서 사용 가능한 형태로 불러들임
prikey = ECC.import_key(x509prikey)

JWSPayload = """{
	"iss":"joe",
	"exp":1300819380,
	"http://example.com/is_root":true
}"""

# 'alg' 필드만 'ES256'으로 수정
JWSProtectedHeader = """{
    "typ":"JWT",
    "alg":"ES256"
}"""
Password = b'your-256-bit-secret'

b64JWSProtectedHeader = base64.urlsafe_b64encode(
    bytes(JWSProtectedHeader, encoding='utf8')).replace(b'=', b'')
b64JWSPayload = base64.urlsafe_b64encode(
    bytes(JWSPayload, encoding='utf8')).replace(b'=', b'')
# JWS 사인을 하기 위한 입력값
JWSSigningInput = b64JWSProtectedHeader + b'.' + b64JWSPayload
JWSSignature = base64.urlsafe_b64encode(
    ES256Sign(prikey, JWSSigningInput)).replace(b'=', b'')
# 보여주기용 print
print(f'{"BASE64URL(UTF8(JWS Protected Header))":30} : {b64JWSProtectedHeader}')
print(f'{"BASE64URL(UTF8(JWS Payload))":30} : {b64JWSPayload}')
print(f'{"JWSSigningInput":30} : {JWSSigningInput}')
print(f'{"JWSSignature":30} : {JWSSignature}')
# 최종 출력물
print("JWS : ", str(JWSSigningInput + b'.' + JWSSignature, 'ascii'))
