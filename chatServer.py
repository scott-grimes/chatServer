import socket, sys, select
import os,hashlib,sqlite3,binascii
from client import client
from encryptionSuite import *

"""
message formatting
keepAlive = 'keepAlive'


login procedure
client sends plaintext login request 'login_request:USERNAME'
server responds with users salt and the public key for encrypting = 'salt:SALT:PUBLICKEY'
client sends encrypted login request 'login_credentials:(USER:PASS) where () is encrypted'

new user procedure
client sends new user request 'new_user:(USERNAME:PASS:SALT) where () is encrypted'

change password procedure
client sends 'change_pass:USER:OLDPASS:NEWPASS'

"""

db = sqlite3.connect('logins.db')

db.execute('''CREATE TABLE IF NOT EXISTS LOGINDATA 
    (USERNAME BLOB PRIMARY KEY,
PASS BLOB NOT NULL,
SALT BLOB NOT NULL);''')

#all info in DB is stored as a unicode string


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
    print('printing all users')
    cursor = db.execute("SELECT * from LOGINDATA")
    for row in cursor:
        print(row)
        print("USER = "+ row[0]+", type:"+type(row[0]))
        print ("PASS = "+row[1]+", type:"+type(row[1]))
        print ("SALT = "+row[2]+", type:"+type(row[2]))
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
        hashed = hashlib.pbkdf2_hmac('sha256',password.encode('base64'),binascii.unhexlify(row[2]),100000)
        if row[1] == binascii.hexlify(hashed):
            return True
    return False

def changePass_server_side(input):
    name = input[0]
    password = input[1]
    newPassword = input[2]
    if(checkPass(name,password)):
        try:
            salt = os.urandom(16)
            password = newPassword.encode('base64')
        
            hashed_pass = hashlib.pbkdf2_hmac('sha256',password,salt,100000)
            hashed_pass = binascii.hexlify(hashed_pass)
            salt = binascii.hexlify(salt)
            db.execute("""UPDATE LOGINDATA     
                SET PASS = ?,    
                    SALT = ?
                WHERE USERNAME = ?;""",(hashed_pass.decode('base64'),salt.decode('base64'),name,))
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

def decodeMessage(message):
    privateKey = importKey('privateKey.txt')
    return decrypt(message,privateKey)
    

def processMessage(message,sock):
    message = message.split(':',1)
    
    if message[0] == 'login_request':
        salt = str(getSalt(message[1]))
        publicKey = importKey('publicKey.txt')
        reply = 'salt:'+salt+':'+publicKey.exportKey('OpenSSH')
            
        sock.sendall(reply.encode('base64'))
        return
    
    if message[0] == 'login_credentials':
        
        try:
            decrypted = decodeMessage(message[1]).split(':')
            login_sucessful = checkPass(decrypted[0],decrypted[1])
        
            if(login_sucessful):
            
                sock.sendall("login:success".encode('base64'))
            else:
                sock.sendall("login:failure".encode('base64'))
        except Exception as e:
            print(e)
        return
    
    
    if message[0] == 'new_user':
        parsed = message[1].split(':')
        if(user_is_in_database(parsed[0])):
            sock.sendall("userExists".encode('base64'))
        else:
            if(add_user_serverSide(parsed)):
                sock.sendall("newUserSucess".encode('base64'))
            else:
                sock.sendall("newUserFailure".encode('base64'))
        return
    
    if message[0] == 'change_pass':
        if(user_is_in_database(message[1])):
            if(changePass_server_side(message[1:])):
                sock.sendall("changePassSucess".encode('base64'))
            else:
                sock.sendall("changePassFailure".encode('base64'))
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
                    data = sock.recv(RECV_BUFFER).decode('base64').strip('\n')
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