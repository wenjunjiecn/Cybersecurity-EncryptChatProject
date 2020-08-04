import hashlib
#hash函数
def hash_sha256(datas): #sha256 哈希函数
    x=hashlib.sha256()
    x.update(datas)
    s=x.hexdigest()
    return s

if __name__ == '__main__':
    e=hash_sha256('你好'.encode('utf-8'))
    print(e)