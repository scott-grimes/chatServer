import socket, sys
from threading import *
import os,hashlib,binascii
from encryptionSuite import *
import time


RECV_BUFFER = 4096
s = None
KEY = None
SALT = None
DEBUG = False
messageCount = 0
loggedIn = False

def processMessage(message):
    if(DEBUG):
        print('recieved:', end='')
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
        if(login_status == 'pass'):
            print('login successful: Welcome {}'.format(userName))
            global loggedIn
            loggedIn = True
            
        else:
            print('login failed')
    if(instruction is 'T'):
        message = message.decode('utf-8').split(' ',1)[1].strip('\n')
        print(message)
        
            

def add_user_clientSide(name, password,sock):
    hashed_pass,salt = hashPassword(password)
    output = ['N',name,hashed_pass,salt]
    send_msg(sock,output)
    

def login(name,password,sock):
    
    global KEY, userName
    userName = name
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
        print('sending: ', end='')
        print(message)
    
    
    
def recv_msg(sock):
        while True:
            try:
                data = sock.recv(RECV_BUFFER)
                if (data is not None):
                    processMessage(data) 
            except socket.timeout:
                pass
            
def read_in_input_msg(sock):
        while True:
            try:
                msg = sys.stdin.readline()
                msg = 'T '+msg
                send_msg(sock,msg.encode('utf-8'))
            except Exception as e:
                print(e)
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
    Thread(target=read_in_input_msg, args=(s,)).start()
    
    
    demo_instructions(s)
    
    while True:
        
        pass 
    
def demo_instructions(sock):
    add_user_clientSide("bob","1234",sock)
    time.sleep(1)
    login("bob","1234",sock)
    time.sleep(1)
    send_msg(sock,'T heres my message'.encode('utf-8'))
        
    
 

    
if __name__== "__main__":
    sys.exit(chatClient())