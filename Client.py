import struct
from tkinter import *
import time
from tkinter import filedialog
import pickle
import socket
import threading
import tkinter.messagebox
from algorithms import AESalgorithm, generateKey, RSAalgorithm, hashalg
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
# CLIENTPUBLIC
# CLIENTPRIVATE
gui_ready = threading.Event()

def initKey():
    global CLIENTPUBLIC, CLIENTPRIVATE
    (CLIENTPRIVATE, CLIENTPUBLIC) = generateKey.generateMyKey("keys/client/client")

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
        if Sock is None:
             txtMsgList.insert(END, "系统消息：尚未连接，无法发送消息\n")
             return
        strMsg = "我:" + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '\n'
        txtMsgList.insert(END, strMsg, 'greencolor')
        Mes = txtMsg.get('0.0', END).strip()
        if not Mes: return
        txtMsgList.insert(END, Mes + '\n')
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
        if Sock is None:
            return
        try:
            while True:
                Message = Sock.recv(BUFF)  # 收到文件
                if not Message: break
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
        except Exception as e:
            print(f"接收消息时发生错误: {e}")
            if txtMsgList:
                txtMsgList.insert(END, f"接收消息时发生错误: {e}\n", 'greencolor')

    def cancelMsg():  # 清空消息内容
        txtMsg.delete('0.0', END)

    def sendMsgEvent(event, Sock):  # 发送消息事件
        if event.keysym == 'Up':
            sendMsg(Sock)
            return "break"

    def UploadAction(event=None):  # 上传文件
        filename = filedialog.askopenfilename()
        print('Selected:', filename)
        initSendSocket(filename)

    def exchangePublicKey(dir):
        global ClientSock, txtMsgList
        if ClientSock is None:
            print("连接未建立，无法发送公钥")
            if txtMsgList:
                txtMsgList.insert(END, "连接未建立，无法发送公钥\n", 'greencolor')
            return
        try:
            with open(dir, 'rb') as fi:
                publicKey = fi.read()
            has = hashalg.hash_sha256(publicKey)
            Message = pickle.dumps([publicKey, has])
            ClientSock.send(Message)
            if txtMsgList:
                txtMsgList.insert(END, "发送公钥成功\n")
        except Exception as e:
            error_msg = f"密钥发送失败: {e}\n"
            print(error_msg)
            if txtMsgList:
                txtMsgList.insert(END, error_msg, 'greencolor')

    def verifyKey(Sock):
        global txtMsgList, SERVERPUBLIC
        if Sock is None:
            return
        try:
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
        except Exception as e:
            print(f"验证密钥时发生错误: {e}")
            if txtMsgList:
                txtMsgList.insert(END, f"验证密钥时发生错误: {e}\n", 'greencolor')

    def cnct():  # 连接操作
        global txtMsgList, ClientSock
        try:
            ClientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ServerAddr = IP
            ClientSock.connect((ServerAddr, PORT))
            print('连接成功，可以开始传输消息和文件了\n')
            if txtMsgList:
                txtMsgList.insert(END, "连接成功，可以开始传输消息和文件了" + IP + ":" + str(PORT) + "\n")
            exchangePublicKey("keys/client/clientpublic.pem")  # 发送公钥
            verifyKey(ClientSock)  # 验证对方密钥
            thread = threading.Thread(target=RecvMsg, args=(ClientSock, None))
            thread.start()
            return ClientSock
        except ConnectionRefusedError:
            error_msg = f"连接被拒绝：无法连接到服务器 {IP}:{PORT}，请确保服务器已启动\n"
            print(error_msg)
            if txtMsgList:
                txtMsgList.insert(END, error_msg, 'greencolor')
            tkinter.messagebox.showwarning('连接失败', f'无法连接到服务器 {IP}:{PORT}\n请确保服务器已启动')
            return None
        except Exception as e:
            error_msg = f"连接错误：{str(e)}\n"
            print(error_msg)
            if txtMsgList:
                txtMsgList.insert(END, error_msg, 'greencolor')
            tkinter.messagebox.showerror('连接错误', f'连接时发生错误：{str(e)}')
            return None

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
        # 以下是生成聊天窗口的代码
        def selectEven(*args):
            print(selal.get())

        global app, frmLT, frmLC, frmLB, txtMsgList, txtMsg, btnSend, btnCancel, btnFile, btnSet
        # 创建窗口
        app = Tk()
        app.title('Client - EncryptChat')
        app.geometry('700x550')
        # app.resizable(0, 0)

        import tkinter.ttk as ttk
        style = ttk.Style()
        style.theme_use('clam')

        # Main Layout
        app.columnconfigure(0, weight=1)
        app.rowconfigure(0, weight=1)

        main_frame = ttk.Frame(app, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=3) # Message list
        main_frame.rowconfigure(1, weight=1) # Input
        main_frame.rowconfigure(2, weight=0) # Controls
        
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
        txtMsg.bind("<KeyPress-Up>", lambda event: sendMsgEvent(event, ClientSocket))

        # Controls Area
        frmLB = ttk.Frame(main_frame)
        frmLB.grid(row=2, column=0, sticky="ew")

        selal = StringVar()
        btnSend = ttk.Button(frmLB, text='发送 (Up)', width=10, command=lambda: sendMsg(ClientSocket))
        btnCancel = ttk.Button(frmLB, text='清空', width=8, command=cancelMsg)
        btnFile = ttk.Button(frmLB, text='上次文件', width=10, command=UploadAction)
        btnSet = ttk.Button(frmLB, text='设置ip', width=8, command=setIpWindows)
        btnAlSel = ttk.Combobox(frmLB, textvariable=selal, state='readonly', width=15)
        btnAlSel['values'] = ('AES-CBC-一次一密', '待定2')
        btnAlSel.current(0)
        btnAlSel.bind("<<ComboboxSelected>>", selectEven)
        
        # Layout controls
        btnSend.pack(side=LEFT, padx=5)
        btnCancel.pack(side=LEFT, padx=5)
        btnAlSel.pack(side=LEFT, padx=5, pady=2) # Align combo nicely

        btnFile.pack(side=RIGHT, padx=5)
        btnSet.pack(side=RIGHT, padx=5)
        
        # Monkey patch insert to be thread safe
        orig_insert = txtMsgList.insert
        txtMsgList.insert = lambda *a: app.after(0, lambda: orig_insert(*a))

        gui_ready.set()
        
        # 主事件循环
        app.mainloop()

    global ClientSocket
    ClientSocket = None

    def connect_thread():
        global ClientSocket
        gui_ready.wait()
        import time
        try:
             ClientSocket = cnct()
             if ClientSocket is None:
                 print("连接失败，可以在GUI中点击'设置ip'按钮重新连接")
        except Exception as e:
             print(f"启动连接时发生错误: {e}")
             import traceback
             traceback.print_exc()

    t = threading.Thread(target=connect_thread)
    t.start()
    
    start()


def main():
    initKey()
    mainPage()


if __name__ == "__main__":
    main()
