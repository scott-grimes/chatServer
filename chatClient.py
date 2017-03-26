import socket, sys
from threading import *
import os,hashlib,binascii
from encryptionSuite import *
import time


RECV_BUFFER = 4096
s = None
KEY = None
SALT = None
DEBUG = True

def processMessage(message):
    if(DEBUG):
        print('recieved:')
        print(message)
    
    instruction = chr(message[0])
    
    if(instruction is 'S'):
        global KEY
        global SALT
        splitMessage = message.decode('utf-8').split(' ',2)
        SALT = splitMessage[1]
        KEY = splitMessage[2]
        KEY = rsa.PublicKey.load_pkcs1(KEY)
        return
    
    if(instruction is 'L'):
        login_status = message.decode('utf-8').split(' ')[1]
            

def add_user_clientSide(name, password,sock):
    hashed_pass,salt = hashPassword(password)
    output = ['N',name,hashed_pass,salt]
    send_msg(sock,output)
    

def login(name,password,sock):
    
    global KEY
    while KEY is None:
        message = ['R',name]
        send_msg(sock,message)
        time.sleep(1)
    raw_text = name+' '+password
    encrypted_credentials = encrypt(raw_text,KEY)
    message = 'C '
    message = message.encode('utf-8')+encrypted_credentials
    send_msg(sock,message)
    
def send_msg(sock,message):
    if (type(message) is bytes):
        sock.sendall(message)
    else:
        message = ' '.join(message)
        sock.sendall(message.encode('utf-8'))
    
    if(DEBUG):
        print(message)
    
    
    
def recv_msg(sock):
        while True:
            try:
                data = sock.recv(RECV_BUFFER)
                if (data is not None):
                    processMessage(data) 
            except socket.timeout:
                pass
            
def chatClient():
    host = 'localhost'
    port = 8888
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(2)
    
    try:
        s.connect((host,port))
        print('connected to {}:{}'.format(host,port))
    except Exception as e:
        print(e)
        sys.exit()  
        
    
        
    Thread(target=recv_msg, args=(s,)).start()
    add_user_clientSide("bob","1234",s)
    login("bob","1234",s)
    while True:
        pass 
    
    
    
 

    
if __name__== "__main__":
    sys.exit(chatClient())