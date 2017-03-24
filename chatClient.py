import socket, sys
from threading import *
import os,hashlib,binascii


RECV_BUFFER = 4096

def processMessage(message):
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
        
    sys.stdout.write('[Me] : ')
    sys.stdout.flush()

    def add_user_clientSide(name, password):
        salt = os.urandom(16)
        password = password.encode()
        
        hashed_pass = hashlib.pbkdf2_hmac('sha256',password,salt,100000)
        hashed_pass = binascii.hexlify(hashed_pass)
        salt = binascii.hexlify(salt)
        
        output = name+":"+hashed_pass.decode()+":"+salt.decode()
        return output
    
    
    def tempSend(sock):
        
        sock.sendall("login_request:bob".encode())
        
        message = "new_user:"+add_user_clientSide('bob','1234')
        sock.sendall(message.encode())
        
        sock.sendall("login_credentials:bob:1234".encode())
        
        message = "new_user:"+add_user_clientSide('bill','asdf')
        
        sock.sendall(message.encode())
        
        
        sock.sendall("change_pass:bill:asdf:xyzt".encode())
        
        sock.sendall("login_credentials:bill:xyzt".encode())
    
    def send_msg(sock):
        tempSend(sock)
        while True:
            data = sys.stdin.readline().encode()
            sock.sendall(data)
    
    def recv_msg(sock):
        while True:
            try:
                data = sock.recv(RECV_BUFFER)
                print(data.decode());
            except socket.timeout:
                pass
    
    Thread(target=send_msg, args=(s,)).start()  
    Thread(target=recv_msg, args=(s,)).start() 
    
    while True:
        pass
   
    
    
 

    
if __name__== "__main__":
    sys.exit(chatClient())