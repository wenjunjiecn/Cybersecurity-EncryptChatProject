import base64
import struct
from tkinter import *
import time
from tkinter import filedialog
import pickle
import socket
import threading
import tkinter.messagebox
from algorithms import AESalgorithm, generateKey, RSAalgorithm, hashalg
import json

# 使用tkinter建立GUI

IP = '127.0.0.1'
PORT = 4396
BUFF = 5120
FIP='127.0.0.1'
FPORT=7932

FPORT=7932
ConSock = None
gui_ready = threading.Event()

# CLIENTPUBLICs
# SERVERPUBLICs
# SERVERPRIVATEs
def initKey():
    global SERVERPUBLICs, SERVERPRIVATEs
    (SERVERPRIVATEs, SERVERPUBLICs) = generateKey.generateMyKey("keys/server/server")

def fileDecrypt(data):
    (message,encrykey)=pickle.loads(data)
    onceKey= RSAalgorithm.RsaDecrypt(encrykey, SERVERPRIVATEs)
    print("接收到的密钥",onceKey,type(onceKey))
    message= AESalgorithm.AesDecrypt(message, onceKey.decode('unicode_escape'))
    message=pickle.loads(message)
    content=base64.b64decode(message['Message'])
    print('传送的内容是',content)
    digest=message['digest']
    if RSAalgorithm.VerRsaSignal(content, digest, CLIENTPUBLICs):
        return content

def initFileListen():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 绑定端口为9001
        s.bind((FIP, FPORT))
        # 设置监听数
        s.listen(10)
    except socket.error as msg:
        print(msg)
        sys.exit(1)
    print('Waiting connection...')

    while True:
        # 等待请求并接受(程序会停留在这一旦收到连接请求即开启接受数据的线程)
        conn, addr = s.accept()
        # 接收数据
        t = threading.Thread(target=deal_data, args=(conn, addr))
        t.start()


def deal_data(conn, addr):
    print('Accept new connection from {0}'.format(addr))
    txtMsgList.insert(END, '文件系统收到一个新的连接，地址来自 {0}'.format(addr), 'greencolor')
    # conn.settimeout(500)
    # 收到请求后的回复
    conn.send('你好,连接建立成功了'.encode('utf-8'))

    while True:
        # 申请相同大小的空间存放发送过来的文件名与文件大小信息
        fileinfo_size = struct.calcsize('128sl')
        # 接收文件名与文件大小信息
        buf = conn.recv(fileinfo_size)
        # 判断是否接收到文件头信息
        if buf:
            # 获取文件名和文件大小
            filename, filesize = struct.unpack('128sl', buf)
            fn = filename.strip(b'\00')
            fn = fn.decode()
            print('file new name is {0}, filesize if {1}'.format(str(fn), filesize))
            txtMsgList.insert(END, '收到的文件名字为 {0}, 文件大小为 {1}'.format(str(fn), filesize), 'greencolor')
            recvd_size = 0  # 定义已接收文件的大小
            # 存储在该脚本所在目录下面
            fp = open('./' + str(fn), 'wb')
            print('start receiving...')
            txtMsgList.insert(END, '开始接受...', 'greencolor')
            # 将分批次传输的二进制流依次写入到文件
            while not recvd_size == filesize:
                if filesize - recvd_size > 1024:
                    lens=conn.recv(1024).decode('utf-8')
                    lens=int(lens)
                    print('该段发送长度为',lens)
                    data = conn.recv(lens)
                    data=fileDecrypt(data)
                    recvd_size += len(data)
                else:
                    lens = conn.recv(1024).decode('utf-8')
                    lens = int(lens)
                    print('该段发送长度为', lens)
                    data = conn.recv(lens)
                    data = fileDecrypt(data)
                    recvd_size = filesize
                conn.send('I have receive the past one'.encode('utf-8'))
                fp.write(data)
            fp.close()
            print('end receive...')
            txtMsgList.insert(END, '接收完毕...', 'greencolor')
        # 传输结束断开连接
        conn.close()
        break


def mainPage():
    def sendMsg(Sock):  # 发送消息
        if Sock is None:
             txtMsgList.insert(END, "系统消息：尚未连接，无法发送消息\n")
             return
        strMsg = "我:" + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '\n'
        txtMsgList.insert(END, strMsg, 'greencolor')
        Mes = txtMsg.get('0.0', END).strip()
        if not Mes: return
        txtMsgList.insert(END, Mes + '\n')
        print(Mes)
        onceKey = AESalgorithm.genKey()  # 一次一密 密钥
        print("oncekey", onceKey)
        digest = RSAalgorithm.RsaSignal(Mes, SERVERPRIVATEs)  # 先hash再签名# 生成消息摘要
        message = {'Message': Mes, 'digest': digest.decode("utf-8")}  # 把消息和摘要打包
        message = json.dumps(message)  # 转成json字符串
        message = AESalgorithm.AesEncrypt(message, onceKey)  # 合并加密
        encrykey = RSAalgorithm.RsaEncrypt(onceKey, CLIENTPUBLICs)  # 用服务器公钥加密一次密钥
        txtMsg.delete('0.0', END)
        Message = pickle.dumps([message, encrykey.decode('utf-8')])  # 序列化消息，用于传输
        Sock.send(Message)

    def RecvMsg(Sock, test):
        global CLIENTPUBLICs
        while True:
            try:
                Message = Sock.recv(BUFF)  # 收到文件
                if not Message: break
                (message, encrykey) = pickle.loads(Message)
                mykey = RSAalgorithm.RsaDecrypt(encrykey, SERVERPRIVATEs)  # 用私钥解密获得一次密钥
                decryMes = AESalgorithm.AesDecrypt(message, mykey.decode('utf-8'))  # 用一次密钥解密消息，获得包含消息内容和摘要的json
                decryMes = json.loads(decryMes)  # 将json转换为python字典
                content = decryMes['Message']
                digest = decryMes['digest'].encode('utf-8')
                if RSAalgorithm.VerRsaSignal(content, digest, CLIENTPUBLICs):
                    strMsg = "对方:" + time.strftime("%Y-%m-%d %H:%M:%S",
                                                   time.localtime()) + "通过数字签名认证,本次密钥为" + mykey.decode('utf-8') + '\n'
                    txtMsgList.insert(END, strMsg, 'greencolor')
                    txtMsgList.insert(END, content + '\n')
            except Exception as e:
                print(e)
                break

    def cancelMsg():  # 取消信息
        txtMsg.delete('0.0', END)

    def sendMsgEvent(event, Sock):  # 发送消息事件
        if event.keysym == 'Up':
            sendMsg(Sock)
            return "break" # Prevent default behavior

    def UploadAction(event=None):
        filename = filedialog.askopenfilename()
        print('Selected:', filename)

    def addSysTip(mes):
        global txtMsgList
        txtMsgList.insert(END, "系统消息：" + mes)

    def exchangePublicKey(dir):
        global ConSock, txtMsgList
        with open(dir, 'rb') as fi:
            publicKey = fi.read()
        # print(publicKey)
        has = hashalg.hash_sha256(publicKey)
        Message = pickle.dumps([publicKey, has])
        try:
            ConSock.send(Message)
            txtMsgList.insert(END, "发送公钥成功\n")
        except:
            txtMsgList.insert(END, "密钥发送失败，正在尝试重新发送...\n")
            exchangePublicKey(dir)

    def verifyKey(Sock):
        global txtMsgList, CLIENTPUBLICs
        while True:
            Message = Sock.recv(BUFF)
            # print("shoudao:",Message)
            (publickey, hash_256) = pickle.loads(Message)
            if hash_256 == hashalg.hash_sha256(publickey):
                txtMsgList.insert(END, "公钥完整性验证完成，可以开始传输文件\n")
                CLIENTPUBLICs = publickey
                txtMsgList.insert(END, "收到公钥\n" + CLIENTPUBLICs.decode('utf-8') + "\n")
                # print("publicc:", CLIENTPUBLICs)
                break
            else:
                txtMsgList.insert(END, "验证失败\n")

    def cnct():
        global txtMsgList, ConSock
        HOSTIP = '127.0.0.1'
        try:
            ServerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ServerSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ServerSock.bind((HOSTIP, PORT))
            ServerSock.listen(8)
            print("本机IP地址为", HOSTIP, "端口号为", PORT, ",正在监听中")
            txtMsgList.insert(END, "系统消息：" + "本机IP地址为" + HOSTIP + "端口号为" + str(PORT) + ",正在监听中\n")
            ConSock, addr = ServerSock.accept()
            print('连接成功')
            txtMsgList.insert(END, "系统消息：连接成功\n")
            exchangePublicKey("keys/server/serverpublic.pem")
            verifyKey(ConSock)
            thread_rev = threading.Thread(target=RecvMsg, args=(ConSock, None))
            thread_rev.start()
            return ConSock
        except Exception as e:
            print(e)
            return None

    def setIpWindows():
        def setNewIP(newip, newport):
            print(newip, newport)
            global IP
            IP = str(newip)
            global PORT
            PORT = int(newport)
            set.destroy()
            try:
                cnct()
            except:
                addSysTip("连接异常，ip或端口不可访问")
                tkinter.messagebox.showwarning('连接失败', '连接异常，ip或端口不可访问\n')
                print("连接异常，ip或端口不可访问\n")

        set = Toplevel()
        set.title('设置ip地址和端口号')
        set.geometry('350x200')
        set.resizable(0, 0)
        
        main_frame = ttk.Frame(set, padding="20")
        main_frame.pack(fill=BOTH, expand=True)

        # ip
        ttk.Label(main_frame, text='IP地址：').grid(row=0, column=0, pady=5, sticky=E)
        ent1 = ttk.Entry(main_frame)
        ent1.grid(row=0, column=1, pady=5, sticky=W)
        # port
        ttk.Label(main_frame, text='端口号：').grid(row=1, column=0, pady=5, sticky=E)
        ent2 = ttk.Entry(main_frame)
        ent2.grid(row=1, column=1, pady=5, sticky=W)
        
        bt_connect = ttk.Button(main_frame, text='连接', command=lambda: setNewIP(ent1.get(), ent2.get()))
        bt_connect.grid(row=2, column=0, columnspan=2, pady=20)

    def start():
        global app, frmLT, frmLC, frmLB, txtMsgList, txtMsg, btnSend, btnCancel, btnFile, btnSet
        # 创建窗口
        app = Tk()
        app.title('Server - EncryptChat')
        app.geometry('600x500')
        # app.resizable(0, 0) # Allow resizing

        import tkinter.ttk as ttk
        style = ttk.Style()
        style.theme_use('clam') # Use a cleaner theme if available, or default

        # Main Layout using Grid
        app.columnconfigure(0, weight=1)
        app.rowconfigure(0, weight=1)

        main_frame = ttk.Frame(app, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=3) # Message list gets more space
        main_frame.rowconfigure(1, weight=1) # Input area
        main_frame.rowconfigure(2, weight=0) # Buttons

        # Message List Area
        frmLT = ttk.Frame(main_frame)
        frmLT.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        frmLT.columnconfigure(0, weight=1)
        frmLT.rowconfigure(0, weight=1)

        scrollbar = ttk.Scrollbar(frmLT)
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        txtMsgList = Text(frmLT, font=('Arial', 12), yscrollcommand=scrollbar.set, highlightthickness=1, borderwidth=1, relief="solid")
        txtMsgList.grid(row=0, column=0, sticky="nsew")
        scrollbar.config(command=txtMsgList.yview)
        
        txtMsgList.tag_config('greencolor', foreground='#008C00', font=('Arial', 10, 'bold'))  # 创建tag

        # Input Area
        frmLC = ttk.Frame(main_frame)
        frmLC.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        frmLC.columnconfigure(0, weight=1)
        frmLC.rowconfigure(0, weight=1)

        txtMsg = Text(frmLC, height=5, font=('Arial', 12), highlightthickness=1, borderwidth=1, relief="solid")
        txtMsg.grid(row=0, column=0, sticky="nsew")
        txtMsg.bind("<KeyPress-Up>", lambda event: sendMsgEvent(event, ConSock))

        # Button Area
        frmLB = ttk.Frame(main_frame)
        frmLB.grid(row=2, column=0, sticky="ew")
        
        btnSend = ttk.Button(frmLB, text='发送 (Up)', width=10, command=lambda: sendMsg(ConSock))
        btnCancel = ttk.Button(frmLB, text='清空', width=8, command=cancelMsg)
        btnFile = ttk.Button(frmLB, text='上传文件', width=10, command=UploadAction)
        btnSet = ttk.Button(frmLB, text='设置ip', width=8, command=setIpWindows)

        btnSend.pack(side=LEFT, padx=5)
        btnCancel.pack(side=LEFT, padx=5)
        btnFile.pack(side=RIGHT, padx=5)
        btnSet.pack(side=RIGHT, padx=5)
        
        # Monkey patch insert to be thread safe
        orig_insert = txtMsgList.insert
        txtMsgList.insert = lambda *a: app.after(0, lambda: orig_insert(*a))
        
        gui_ready.set()
        
        # 主事件循环
        app.mainloop()

    def connect_thread():
        global ConSock
        gui_ready.wait()
        try:
            ConSock = cnct()
        except:
             addSysTip("连接异常，ip或端口不可访问")
             tkinter.messagebox.showwarning('连接失败', '连接异常，ip或端口不可访问，点击设置按钮重新设置\n')
             print("连接异常，ip或端口不可访问\n")

    t = threading.Thread(target=connect_thread)
    t.start()

    start()


def main():
    initKey()
    thread_1=threading.Thread(target=initFileListen)
    thread_1.start()
    mainPage()
    # thread_2.start()


if __name__ == "__main__":
    main()
