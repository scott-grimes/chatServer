import socket, sys
from threading import *

RECV_BUFFER = 4096



def chatClient():
    
    print('Pychat V1')  
    if len(sys.argv)<3 :
        #print('Usage : python chatClient.py hostname port')
        host = 'localhost'
        port = 8888
        #sys.exit()
    else:
        host = sys.argv[1]
        port = int(sys.argv[2])
    
    
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
    
    def send_msg(sock):
        while True:
            data = sys.stdin.readline()
            sys.stdout.write('\r')
            sock.sendall(data)
            sys.stdout.write('[Me] : ')
            sys.stdout.flush()
    
    def recv_msg(sock):
        while True:
            try:
                data = sock.recv(RECV_BUFFER)
                sys.stdout.write("\r"+data);
                sys.stdout.write('[Me] :'); sys.stdout.flush()
            except socket.timeout:
                pass
    
    Thread(target=send_msg, args=(s,)).start()  
    Thread(target=recv_msg, args=(s,)).start() 
    while True:
        pass
   
    
    
 

    
if __name__== "__main__":
    sys.exit(chatClient())