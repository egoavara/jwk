# %%
import base64
import hashlib
import hmac


# JWSPayload = """{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}"""
# JWSProtectedHeader = """{"typ":"JWT",\r\n "alg":"HS256"}"""
# Password = base64.urlsafe_b64decode(
# "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow==")

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
JWSSignature = base64.urlsafe_b64encode(hmac.new(
    Password, JWSSigningInput, hashlib.sha256).digest()).replace(b'=', b'')
# 보여주기용 print
print(f'{"BASE64URL(UTF8(JWS Protected Header))":30} : {b64JWSProtectedHeader}')
print(f'{"BASE64URL(UTF8(JWS Payload))":30} : {b64JWSPayload}')
print(f'{"JWSSigningInput":30} : {JWSSigningInput}')
print(f'{"JWSSignature":30} : {JWSSignature}')
# 최종 출력물
print("JWS : ", str(JWSSigningInput + b'.' + JWSSignature, 'ascii'))
