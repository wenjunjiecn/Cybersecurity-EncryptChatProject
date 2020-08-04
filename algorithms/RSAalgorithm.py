from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
import base64
random_generator= Random.new().read
print("rand:",random_generator)
def RsaEncrypt(message,key):
    rsakey = RSA.importKey(key) #生成RSA密钥对象
    cipher = Cipher_pkcs1_v1_5.new(rsakey)   #生成一个pkcs1 对象
    if isinstance(message,str):
        message=message.encode('utf-8')
    cipher_text = base64.b64encode(cipher.encrypt(message)) #生成一个bytes对象
    print(cipher_text.decode('utf-8'))
    return cipher_text  #返回一个bytes对象，如果要显示需要utf8编码
def RsaDecrypt(encrypt_text,key):
    global random_generator
    rsakey = RSA.importKey(key)
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    if isinstance(encrypt_text,str):
        encrypt_text=base64.b64decode(encrypt_text)
    text = cipher.decrypt(encrypt_text,random_generator)
    print("测试点test",type(text))
    return text    #返回bytes对象，显示需要utf8编码

def RsaSignal(message,key):
    if isinstance(message,str):
        message=message.encode()
    rsakey = RSA.importKey(key)
    signer = Signature_pkcs1_v1_5.new(rsakey)
    digest = SHA.new()
    digest.update(message)
    sign = signer.sign(digest)
    signature = base64.b64encode(sign)
    print(signature)
    return signature

def VerRsaSignal(message,signature,key):
    if isinstance(message,str):
        message=message.encode()
    print("signtype",type(signature))
    rsakey = RSA.importKey(key)
    verifier = Signature_pkcs1_v1_5.new(rsakey)

    digest = SHA.new()
    # Assumes the data is base64 encoded to begin with
    digest.update(message)

    is_verify = verifier.verify(digest, base64.b64decode(signature))
    print(is_verify)
    return is_verify

if __name__ == '__main__':
    mes='你好yo'
    pubkey='''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvSChFb9Y6xwb+XTMIcHR
Q5lujD1J7v93TwJvUE7e6SEVpQEjfFKpjVEFpJUONdagBRYYkO4TA6k9gpAPmPCF
nucttQBMAkTMDtxLndOKI0MOc5THw0h1fschm6CyJzkGoVYlPr0vU2Oq10yK0s7y
uYqTzJB5sOLjRCGxdIw9V3UmpggK+IfQ6yXrM/dXy4h13zR6IzHnJ8tBH0VvvPes
z/fMrN/HWw6av13CZuS12qEU/Jij+8ZvpKxn6kd1BO4+g9UW4ExsEq95+qFTOJIj
hlm7yJCCsHfNq/r1nIa/NbpigQG0TS26r8sWTLgPmYysBTONFwX+NtCbbESRwRMo
gQIDAQAB
-----END PUBLIC KEY-----'''
    prikey='''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvSChFb9Y6xwb+XTMIcHRQ5lujD1J7v93TwJvUE7e6SEVpQEj
fFKpjVEFpJUONdagBRYYkO4TA6k9gpAPmPCFnucttQBMAkTMDtxLndOKI0MOc5TH
w0h1fschm6CyJzkGoVYlPr0vU2Oq10yK0s7yuYqTzJB5sOLjRCGxdIw9V3UmpggK
+IfQ6yXrM/dXy4h13zR6IzHnJ8tBH0VvvPesz/fMrN/HWw6av13CZuS12qEU/Jij
+8ZvpKxn6kd1BO4+g9UW4ExsEq95+qFTOJIjhlm7yJCCsHfNq/r1nIa/NbpigQG0
TS26r8sWTLgPmYysBTONFwX+NtCbbESRwRMogQIDAQABAoIBABCU9cqkVjV253T9
qpAjICffIfQlw3+y4lEJE51k7OJfxjgLW4Mg9ECxo98EOpS51pnbkBfU59HgWsZB
vzxXij+eYUGHXyKryYBcDD0wOOJSlMfJeaJDjhmpd+bfNf9+Xnhyxx0zFR0olef+
jAVjo6Bk6AR9fk3l9qsYkSh4y0AJnJuPnMjISqjn6LfGXf1VAVCkHljLRTHzIzw3
ZbV1rNWNQq8znaNGQP1sGAXpu1x+XfQFJZVUDtVeC9E2bB3TQe5D+LIFCtZrUkpK
PNOCqce9oOUgErUub73+fTMMvBX5rU2m6zuhmZjl9s8PHVsDv1/GMyU/6Krrhh8E
n11ipEkCgYEAw+oFfJhs4DtC+IqC0WaI4v6BB4EoYDoaAhHjNQZ0gx5k1AtIeNpN
YKCFF0IPyIQbDWve+hspxJ47zcOZuS85UfRFjkfohwYE4UdhViUAwsIiFePZMEz8
3R2XGL0lHbXnZ2KRD0u9w+u9YfPLngsnHBUZxRp7iG48apP2nYfRCrcCgYEA9yHC
NOVb7ER9NMrSRkCCh6qM0jPUsCFFBPv63s6ZKKioyqHYUPVPP9ZxxsQpya+NUPiS
vf56ccGFqtjKMDIMQh+POTPkFEyjFHwoxXxg76xz2uCpyQVsSQTNCwy9LkEavjNe
sebB+a8iH2gTL5zIXObaTBC4iANhQ+OtR6BDjocCgYAVT6qjIA2P4sJpON/8GVRA
pQCyKUmUFh3oJbv6c6ZO8Qp0ynlqtAyAu1Ve70+6NyyeLCLIQBYuDixhOKrLKyjo
ElNSo93WekAjpVkgPswzY1zD1tI0X9uNzf82sLSN49C1PVKcQFf3LPif5B49Jedu
NZllCHlxoNQvn8LO5gxGRwKBgQCD+CYSQyy8VbKa33g8hbRuqBe9JGp+h7WovLqy
ApdtS+ufEaBHU0g3qddmMliyWCnZxHPwO5W9a39qxYvrAr7jDKFaBajVYjtv9AF9
vDazpl7T0kc4jsnNkF/Cd9IKgj+6tAnsbHLHV8ucA+LC+TFR0wFdv0wbbdqh+1IM
Prv0vwKBgFUAow5ttHgBtG5Ap4evsRgWzGaF2wOGzEOK3rwS5fIGY67A1YN35Q+C
SmkGVcozf8rFeyMCwk68XoLff1i14iQDAarAjvdWo0ww/gjA50kdrgFb7FpjbZNE
0kOV6q4vFJIjT8g2CeJ1MmBEuHhflC+gNBWmlEs+xaghA7/cbop2
-----END RSA PRIVATE KEY-----'''
    a=RsaEncrypt(mes,pubkey)
    b=RsaDecrypt(a,prikey)
    c=RsaSignal(mes,prikey)




    digitttt='IUvR9162yrRtQAfhhVZrefB9yCwSL+kf81iudLqcDyKesokwvhjZeOpUlXR7zYOokThhelPrqtE4DIsXIxNb7FY9QgwLFkCGSQG17h09FJaZQmDLaUmtDutXDFgGZ9j5Mzln1nCtOWDreey9YbeJaRsDRj4jjp1ZOCdsC8pN65M='
    digitttt=digitttt.encode('utf-8')
    pppuuu='''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCsCp6xhC5Tr7ucaRNU3aKMsvv8
PtxlQdl4LTys5F6wKM11MeJSXwruiUBbDHhySLfy5ZPpYxsfa5ez6hbaZoMyk+xd
p1jWehUWqouFA/OmHxQ4jjmhxJ40cNcm/TAkyl8zci0uGaird26x2NUa4o8BpnE5
TokPhvYzdhsx05FQuwIDAQAB
-----END PUBLIC KEY-----'''
    pppuuu=pppuuu.encode('utf-8')
    mess='你好，世界'
    d = VerRsaSignal(mess, digitttt, pppuuu)
    print("d",d)