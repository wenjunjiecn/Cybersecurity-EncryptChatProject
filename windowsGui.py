import struct
from tkinter import *
import time
from tkinter import filedialog
import RSAalgorithm
import pickle
import socket
import threading
import tkinter.messagebox
import generateKey
import hashalg
import AESalgorithm
from tkinter import ttk
import json
import os
import base64

# 使用tkinter建立GUI

IP = '127.0.0.1'
PORT = 4396
BUFF = 5120
FIP='127.0.0.1'
FPORT=7932

# SERVERPUBLIC
# CLIENTPUBLIC
# CLIENTPRIVATE
def initKey():
    global CLIENTPUBLIC, CLIENTPRIVATE
    (CLIENTPRIVATE, CLIENTPUBLIC) = generateKey.generateMyKey("./client/client")

def fileEncrypt(data):
    onceKey = AESalgorithm.genKey()
    print("发送的密钥",onceKey)
    digest = RSAalgorithm.RsaSignal(data, CLIENTPRIVATE)
    message = {'Message': base64.b64encode(data), 'digest': digest.decode("utf-8")}  # 把消息和摘要打包
    message = pickle.dumps(message)  # 转成json字符串
    message = AESalgorithm.AesEncrypt(message, onceKey)
    encrykey = RSAalgorithm.RsaEncrypt(onceKey, SERVERPUBLIC)
    MES = pickle.dumps([message, encrykey.decode('utf-8')])
    return MES





def initSendSocket(filepath):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((FIP, FPORT))
    except socket.error as msg:
        print(msg)
        sys.exit(1)
    print(s.recv(10240))

    # 需要传输的文件路径

    # 判断是否为文件
    if os.path.isfile(filepath):
        # 定义定义文件信息。128s表示文件名为128bytes长，l表示一个int或log文件类型，在此为文件大小
        fileinfo_size = struct.calcsize('128sl')
        # 定义文件头信息，包含文件名和文件大小
        fhead = struct.pack('128sl', os.path.basename(filepath).encode('utf-8'), os.stat(filepath).st_size)
        # 发送文件名称与文件大小
        s.send(fhead)

        # 将传输文件以二进制的形式分多次上传至服务器
        fp = open(filepath, 'rb')
        while True:
            global rere
            rere=''
            data = fp.read(1024)
            if not data:
                print('{0} 文件发送完毕...'.format(os.path.basename(filepath)))
                txtMsgList.insert(END, '{0} 文件发送完毕...'.format(os.path.basename(filepath)), 'greencolor')
                break
            print("发送的内容",data)
            tosend=fileEncrypt(data)
            s.send(str(len(tosend)).encode('utf-8'))
            s.send(tosend)
            while True:
                if s.recv(1024).decode('utf-8')=='I have receive the past one':
                    break


        # 关闭当期的套接字对象
        s.close()



# 主页
def mainPage():
    def sendMsg(Sock):  # 发送消息
        strMsg = "我:" + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '\n'
        txtMsgList.insert(END, strMsg, 'greencolor')
        Mes = txtMsg.get('0.0', END)
        txtMsgList.insert(END, Mes)
        onceKey = AESalgorithm.genKey()  # 一次一密 密钥
        digest = RSAalgorithm.RsaSignal(Mes, CLIENTPRIVATE)  # 先hash再签名# 生成消息摘要
        message = {'Message': Mes, 'digest': digest.decode("utf-8")}  # 把消息和摘要打包
        message = json.dumps(message)  # 转成json字符串
        message = AESalgorithm.AesEncrypt(message, onceKey)  # 合并加密
        encrykey = RSAalgorithm.RsaEncrypt(onceKey, SERVERPUBLIC)  # 用服务器公钥加密一次密钥
        txtMsg.delete('0.0', END)
        Message = pickle.dumps([message, encrykey.decode('utf-8')])  # 序列化消息，用于传输
        Sock.send(Message)

    def RecvMsg(Sock, test):  # 接受消息函数
        global SERVERPUBLICs
        while True:
            Message = Sock.recv(BUFF)  # 收到文件
            (message, encrykey) = pickle.loads(Message)

            mykey = RSAalgorithm.RsaDecrypt(encrykey, CLIENTPRIVATE)  # 用私钥解密获得一次密钥
            print('mykey', mykey.decode('utf-8'))
            decryMes = AESalgorithm.AesDecrypt(message, mykey.decode('utf-8'))  # 用一次密钥解密消息，获得包含消息内容和摘要的json
            decryMes = json.loads(decryMes)  # 将json转换为python字典
            content = decryMes['Message']
            digest = decryMes['digest'].encode('utf-8')

            if RSAalgorithm.VerRsaSignal(content, digest, SERVERPUBLIC):
                strMsg = "对方:" + time.strftime("%Y-%m-%d %H:%M:%S",
                                               time.localtime()) + "通过数字签名认证,本次密钥为" + mykey.decode('utf-8') + '\n'
                txtMsgList.insert(END, strMsg, 'greencolor')
                txtMsgList.insert(END, content + '\n')

    def cancelMsg():  # 清空消息内容
        txtMsg.delete('0.0', END)

    def sendMsgEvent(event, Sock):  # 发送消息事件
        if event.keysym == 'Up':
            sendMsg(Sock)

    def UploadAction(event=None):  # 上传文件
        filename = filedialog.askopenfilename()
        print('Selected:', filename)
        initSendSocket(filename)

    def exchangePublicKey(dir):
        global ClientSock, txtMsgList
        with open(dir, 'rb') as fi:
            publicKey = fi.read()
        has = hashalg.hash_sha256(publicKey)
        Message = pickle.dumps([publicKey, has])
        try:
            ClientSock.send(Message)
            txtMsgList.insert(END, "发送公钥成功\n")
        except:
            txtMsgList.insert(END, "密钥发送失败，正在尝试重新发送...\n")
            exchangePublicKey(dir)

    def verifyKey(Sock):
        global txtMsgList, SERVERPUBLIC
        while True:
            Message = Sock.recv(BUFF)
            (publickey, hash_256) = pickle.loads(Message)
            if hash_256 == hashalg.hash_sha256(publickey):
                txtMsgList.insert(END, "公钥完整性验证完成，可以开始传输文件\n")
                SERVERPUBLIC = publickey
                txtMsgList.insert(END, "收到公钥\n" + SERVERPUBLIC.decode('utf-8') + "\n")

                break
            else:
                txtMsgList.insert(END, "验证失败\n")

    def cnct():  # 连接操作
        global txtMsgList, ClientSock
        ClientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ServerAddr = IP
        ClientSock.connect((ServerAddr, PORT))
        print('连接成功，可以开始传输消息和文件了\n')
        txtMsgList.insert(END, "连接成功，可以开始传输消息和文件了" + IP + ":" + str(PORT) + "\n")
        exchangePublicKey("./client/clientpublic.pem")  # 发送公钥
        verifyKey(ClientSock)  # 验证对方密钥
        thread = threading.Thread(target=RecvMsg, args=(ClientSock, None))
        thread.start()
        return ClientSock

    def setIpWindows():  # 设置ip的子窗口
        def setNewIP(newip, newport):
            global txtMsgList
            print(newip, newport)
            global IP
            IP = str(newip)
            global PORT
            PORT = int(newport)
            set.destroy()
            try:
                cnct()
            except:
                txtMsgList.insert(END, "连接异常，ip或端口不可访问")
                tkinter.messagebox.showwarning('连接失败', '连接异常，ip或端口不可访问\n')
                print("连接异常，ip或端口不可访问\n")

        set = Tk()
        set.title('设置ip地址和端口号')
        set.geometry('350x200')
        set.resizable(0, 0)
        # ip
        Label(set, text='IP地址：').place(x=10, y=10)
        ent1 = Entry(set)
        ent1.place(x=150, y=10)
        # port
        Label(set, text='端口号：').place(x=10, y=50)
        ent2 = Entry(set)
        ent2.place(x=150, y=50)
        bt_connect = Button(set, text='连接', command=lambda: setNewIP(ent1.get(), ent2.get()))
        bt_connect.place(x=150, y=130)
        set.mainloop()

    def start():
        # 以下是生成聊天窗口的代码
        def selectEven(*args):
            print(selal.get())

        global app, frmLT, frmLC, frmLB, txtMsgList, txtMsg, btnSend, btnCancel, btnFile, btnSet
        # 创建窗口
        app = Tk()
        app.title('网络加密软件-Client')
        app.resizable(0, 0)

        # 创建frame容器
        frmLT = Frame(width=500, height=320, bg='white')
        frmLC = Frame(width=500, height=150, bg='white')
        frmLB = Frame(width=500, height=30)
        # frmRT = Frame(width = 200, height = 500)

        # 创建控件
        txtMsgList = Text(frmLT)
        txtMsgList.tag_config('greencolor', foreground='#008C00')  # 创建tag
        txtMsg = Text(frmLC)
        txtMsg.bind("<KeyPress-Up>", sendMsgEvent)
        selal = StringVar()
        btnSend = Button(frmLB, text='发送', width=8, command=lambda: sendMsg(ClientSocket))
        btnCancel = Button(frmLB, text='取消', width=8, command=cancelMsg)
        btnFile = Button(frmLB, text='上次文件', width=8, command=UploadAction)
        btnSet = Button(frmLB, text='设置ip', width=8, command=setIpWindows)
        btnAlSel = ttk.Combobox(frmLB, textvariable=selal, state='readonly')
        btnAlSel['values'] = ('AES-CBC-一次一密', '待定2')
        btnAlSel.current(0)
        btnAlSel.bind("<<ComboboxSelected>>", selectEven)
        print("selal is ", selal.get())
        # btnFile.pack()
        # imgInfo = PhotoImage(file = "timg-2.gif")
        # lblImage = Label(frmRT, image = imgInfo)
        # lblImage.image = imgInfo

        # 窗口布局
        frmLT.grid(row=0, column=0, columnspan=2, padx=1, pady=3)
        frmLC.grid(row=1, column=0, columnspan=2, padx=1, pady=3)
        frmLB.grid(row=2, column=0, columnspan=2)
        # frmRT.grid(row = 0, column = 2, rowspan = 3, padx =2, pady = 3)

        # 固定大小
        frmLT.grid_propagate(0)
        frmLC.grid_propagate(0)
        frmLB.grid_propagate(0)
        # frmRT.grid_propagate(0)

        btnSend.grid(row=2, column=0)
        btnCancel.grid(row=2, column=1)
        btnFile.grid(row=2, column=2)
        btnSet.grid(row=2, column=3)
        btnAlSel.grid(row=2, column=4)
        # lblImage.grid()
        txtMsgList.grid()
        txtMsg.grid()
        # 主事件循环
        app.mainloop()

    thread_gui = threading.Thread(target=start)
    thread_gui.start()

    ClientSocket = cnct()
    # try:
    #     ClientSocket=cnct()
    # except:
    #     addSysTip("连接异常，ip或端口不可访问")
    #     tkinter.messagebox.showwarning('连接失败', '连接异常，ip或端口不可访问，点击设置按钮重新设置\n')
    #     print("连接异常，ip或端口不可访问\n")


def main():
    initKey()
    mainPage()


if __name__ == "__main__":
    main()
