import socket, sys, select

HOST = ''
PORT = 8888
RECV_BUFFER = 4096
SOCKET_LIST = []

def chat_server():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST,PORT))
        s.listen(10)
        print("Chat Server Started on PORT {}".format(PORT))
        
    except Exception as e:
        print(e)
    SOCKET_LIST.append(s)
    
    while True:
        ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)
        
        for sock in ready_to_read:
            #new client joined!
            if sock == s:
                conn, addr = s.accept()
                SOCKET_LIST.append(conn)
                print('Client {}:{} connected'.format(addr[0],str(addr[1])))
                conn.sendall('Welcome to our Server!\n')
                broadcast(s,conn,"{}:{} has joined\n".format(addr[0],str(addr[1])))
                
            #a message from a client
            else:
                try:
                    data = sock.recv(RECV_BUFFER)
                    print('{}:{}: '.format(addr[0],str(addr[1]))+data.strip('/n'))
                    if data:
                        #if data is "^":
                         #   if sock in SOCKET_LIST:
                          #      SOCKET_LIST.remove(sock)
                           #     broadcast(s,sock,"{} has left".format(sock.address))
                                
                        broadcast(s,sock,'{}:{}: '.format(addr[0],str(addr[1]))+data.strip('/n'))
                    else:
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)
                        broadcast(s,sock,"{} is offline".format(sock.address))
                except:
                    #broadcast(s,sock,"client disconnected")
                    continue
    s.close()
            
def broadcast(server,sock,message):
    for socket in SOCKET_LIST:
        if socket is not server and socket is not sock:
            try:
                socket.sendall(message)
            except:
                socket.close()
                if socket in SOCKET_LIST:
                    SOCKET_LIST.remove(socket)

if __name__ == "__main__":
    sys.exit(chat_server())