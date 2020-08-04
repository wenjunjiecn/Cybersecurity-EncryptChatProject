import base64
from Crypto.Cipher import AES
import random
import string

# 采用AES对称加密算法,CBC


iv=b'0000100010010010'
# str不是16的倍数那就补足为16的倍数
def add_to_16(value):
    if isinstance(value,bytes):
        value.decode()
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode(value)  # 返回bytes
#加密方法
def AesEncrypt(data,key):
    if isinstance(data,bytes):
        text=base64.b64encode(data).decode('ascii')
    else:
        text = base64.b64encode(data.encode('utf-8')).decode('ascii')
    # 初始化加密器
    aes = AES.new(add_to_16(key), AES.MODE_CBC,IV=iv)
    #先进行aes加密
    encrypt_aes = aes.encrypt(add_to_16(text))
    #用base64转成字符串形式
    encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  # 执行加密并转码返回bytes
    return encrypted_text
#解密方法
def AesDecrypt(text,key):
    # 初始化加密器
    aes = AES.new(add_to_16(key), AES.MODE_CBC,IV=iv)
    #优先逆向解密base64成bytes
    if isinstance(text,str):
        base64_decrypted = base64.decodebytes(text.encode(encoding='utf-8'))
    else:
        base64_decrypted=base64.decodebytes(text)
    decrypted_text = str(aes.decrypt(base64_decrypted),encoding='utf-8') # 执行解密密并转码返回str
    decrypted_text = base64.b64decode(decrypted_text.encode('utf-8'))\
        # .decode('utf-8')
    return decrypted_text


def genKey():
    source=string.ascii_letters+string.digits
    key="".join(random.sample(source,16))
    return key

if __name__ == '__main__':
    text='你好你好'
    mykey=genKey()
    print("加密密钥是"+mykey)
    e=AesEncrypt(text,mykey)
    d=AesDecrypt(e,mykey)
    print(e)
    print(d)