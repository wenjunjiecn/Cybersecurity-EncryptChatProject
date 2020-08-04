import Crypto.PublicKey.RSA
import Crypto.Random
#生成密钥
#利用库中默认的generate来生成
def generateMyKey(dir):
    x = Crypto.PublicKey.RSA.generate(1024)
    privateKey = x.exportKey("PEM")  # 生成私钥
    publicKey = x.publickey().exportKey()  # 生成公钥
    with open(dir+"private.pem", "wb") as x:
        x.write(privateKey)
    with open(dir+"public.pem", "wb") as x:
        x.write(publicKey)
    return(privateKey,publicKey)


