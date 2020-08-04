import socket
import threading
import pickle
from algorithms import RSAalgorithm

HOSTIP='127.0.0.1'
PORT = 4396
BUFF = 1024


def SendMessage(Sock, test):
    while True:
        SendData = input()
        (encryptdata, PrivateKey) = RSAalgorithm.RsaEncrypt(SendData)
        print('encrypted data is ' + str(encryptdata))
        Message = pickle.dumps([encryptdata, PrivateKey])
        if len(SendData) > 0:
            Sock.send(Message)


def RecvMessage(Sock, test):
    while True:
        Message = Sock.recv(BUFF)
        (recvdata, PrivateKey) = pickle.loads(Message)
        decryptdata = RSAalgorithm.RsaDecrypt(recvdata, PrivateKey)
        if len(Message) > 0:
            print("receive message:" + decryptdata)


# 获取本机ip地址
def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip


def main():
    HOSTIP = '127.0.0.1'
    ServerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ServerSock.bind((HOSTIP, PORT))
    ServerSock.listen(8)
    print("本机IP地址为",HOSTIP,"端口号为",PORT,",正在监听中")
    while True:
        ConSock, addr = ServerSock.accept()
        print('connection succeed' + '\n' + 'you can chat online')
        thread_1 = threading.Thread(target=SendMessage, args=(ConSock, None))
        thread_2 = threading.Thread(target=RecvMessage, args=(ConSock, None))
        thread_1.start()
        thread_2.start()





if __name__ == '__main__':
    main()
