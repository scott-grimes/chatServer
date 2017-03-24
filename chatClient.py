import socket, sys
from threading import *
import os,hashlib,binascii
from encryptionSuite import *
import time
from Crypto.PublicKey.RSA import importKey as stringToKey


RECV_BUFFER = 4096
s = None
KEY = None
SALT = None


def processMessage(message):
    
    if(message[:4] == 'salt'):
        global KEY
        global SALT
        splitMessage = message.split(":",2)
        SALT = splitMessage[1] 
        KEY = stringToKey(splitMessage[2])
        return
    if(message[:6] == 'login:'):
        login_status = message.split(':')[1]
            

def add_user_clientSide(name, password,sock):
    salt = os.urandom(16)
    password = password.encode('base64')
    
    hashed_pass = hashlib.pbkdf2_hmac('sha256',password,salt,100000)
    hashed_pass = binascii.hexlify(hashed_pass)
    salt = binascii.hexlify(salt)
    
    output = 'new_user:'+name+":"+hashed_pass+":"+salt
    sock.sendall(output.encode('base64'))
    

def login(name,password,sock):
    global KEY
    while KEY is None:
        sock.sendall(("login_request:"+name).encode('base64'))
        time.sleep(1)
    
    raw_text = name+':'+password
    encrypted_credentials = encrypt(raw_text,KEY)
    message = "login_credentials:"+encrypted_credentials
    sock.sendall(message.encode('base64'))
    
def recv_msg(sock):
        while True:
            try:
                data = sock.recv(RECV_BUFFER).decode('base64')
                if (data is not None):
                    print('recieved: '+data)
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
    add_user_clientSide('bob','1234',s)
    login('bob','1234',s)
    while True:
        pass 
    
    
    
 

    
if __name__== "__main__":
    sys.exit(chatClient())