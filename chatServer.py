import socket, sys, select
import os,hashlib,sqlite3,binascii
from client import client
from Crypto.Cipher import AES

"""
message formatting
keepAlive = 'keepAlive'


login procedure
client sends plaintext login request 'login_request:USERNAME'
server responds with users salt and a unique key for encrypting = 'salt:SALT:UNIQUEKEY'
client sends encrypted login request 'login_credentials:USER:PASS'
server decrypts all communications at this point

new user procedure
client sends plaintext new user request 'new_user:USERNAME:PASS:SALT'

change password procedure
client sends 'change_pass:USER:OLDPASS:NEWPASS'

"""

db = sqlite3.connect('logins.db')

db.execute('''CREATE TABLE IF NOT EXISTS LOGINDATA 
    (USERNAME BLOB PRIMARY KEY,
PASS BLOB NOT NULL,
SALT BLOB NOT NULL);''')


HOST = ''
PORT = 8888
RECV_BUFFER = 4096
SOCKET_LIST = []
USER_LIST = [] 


    
            
def broadcast(server,sock,message):
    #sends a message to everyone on the server
    for socket in SOCKET_LIST:
        if socket is not server and socket is not sock:
            try:
                socket.sendall(message)
            except:
                socket.close()
                if socket in SOCKET_LIST:
                    SOCKET_LIST.remove(socket)
                    
                    
def print_all_users():
    cursor = db.execute("SELECT * from LOGINDATA")
    for row in cursor:
        print(row)
        print("USER = "+ row[0])
        print ("PASS = "+ str(row[1]))
        print ("SALT = "+ str(row[2]))
        print("")

def user_is_in_database(name):
    cursor = db.execute("SELECT * from LOGINDATA WHERE USERNAME IS ?",(name,))
    row = cursor.fetchone()
    return (row is not None)

def add_user_serverSide(input):
    name = input[0]
    password = input[1]
    salt = input[2]
    
    if (not user_is_in_database(name)):
        db.execute("INSERT INTO LOGINDATA (USERNAME,PASS,SALT) \
    VALUES (?,?,?);",(name,password,salt))
        db.commit()
        return True
    
    return False


def checkPass(name, password):
    cursor = db.execute("SELECT * from LOGINDATA WHERE USERNAME IS ?",(name,))
    row = cursor.fetchone()
    if row is not None:
        hashed = hashlib.pbkdf2_hmac('sha256',password.encode(),binascii.unhexlify(row[2].encode()),100000)
        if row[1] == binascii.hexlify(hashed).decode():
            return True
    return False

def changePass_server_side(input):
    name = input[0]
    password = input[1]
    newPassword = input[2]
    if(checkPass(name,password)):
        try:
            salt = os.urandom(16)
            password = newPassword.encode()
        
            hashed_pass = hashlib.pbkdf2_hmac('sha256',password,salt,100000)
            hashed_pass = binascii.hexlify(hashed_pass)
            salt = binascii.hexlify(salt)
            db.execute("""UPDATE LOGINDATA     
                SET PASS = ?,    
                    SALT = ?
                WHERE USERNAME = ?;""",(hashed_pass.decode(),salt.decode(),name,))
            db.commit()
            print('pass changed')
            return True
        except Exception as e:
            print(e)    
        return False
        

def getSalt(name):
    if(user_is_in_database(name)):
        cursor = db.execute("SELECT SALT from LOGINDATA WHERE USERNAME IS ?",(name,))
        salt = cursor.fetchone()[0]
        return salt
    return 'None'

def decodeMessage(message,sock):
    
    pass

def processMessage(message,sock):
    
    message = message.split(':')
    print(message)
    if message[0] == 'login_request':
        salt = getSalt(message[1])
        reply = 'salt:'+salt
        sock.sendall(reply.encode())
        return
    if message[0] == 'login_credentials':
        
        login_sucessful = checkPass(message[1],message[2])
        print("done")
        if(login_sucessful):
            key = 'fasoaklvah82olasdf'
            
            newClient = client(sock,message[1],getSalt(message[1]),key)
            
            sock.sendall("login success".encode())
        else:
            sock.sendall("login failure".encode())
        return
    if message[0] == 'new_user':
        if(user_is_in_database(message[1])):
            sock.sendall("userExists".encode())
        else:
            if(add_user_serverSide(message[1:])):
                sock.sendall("newUserSucess".encode())
            else:
                sock.sendall("newUserFailure".encode())
        return
    if message[0] == 'change_pass':
        if(user_is_in_database(message[1])):
            if(changePass_server_side(message[1:])):
                sock.sendall("changePassSucess".encode())
            else:
                sock.sendall("changePassFailure".encode())
        return
        

    
    
def chat_server():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST,PORT))
        s.listen(10)
        print("Server Started on PORT {}".format(PORT))
        
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
                
            #a message from a client
            else:
                try:
                    data = sock.recv(RECV_BUFFER).decode().strip('\n')
                    
                    if data:
                        processMessage(data,sock)   
                    else:
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)
                        broadcast(s,sock,"{} is offline".format(sock.address))
                except:
                    #broadcast(s,sock,"client disconnected")
                    continue
    s.close()
    
if __name__ == "__main__":
    
    sys.exit(chat_server())