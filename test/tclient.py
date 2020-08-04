import socket
import threading
import pickle
from algorithms import RSAalgorithm

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
    ClientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ServerAddr = input("请输入您要通讯的ip地址")
    ServerAddr ="127.0.0.1"
    ClientSock.connect((ServerAddr, PORT))
    print('连接成功，可以开始传输消息和文件了')
    thread_3 = threading.Thread(target=SendMessage, args=(ClientSock, None))
    thread_4 = threading.Thread(target=RecvMessage, args=(ClientSock, None))
    thread_3.start()
    thread_4.start()



if __name__ == '__main__':
    main()
