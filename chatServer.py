import socket, sys, select
import os,hashlib,sqlite3,binascii
from client import client
from encryptionSuite import *

"""
message formatting
keepAlive = 'keepAlive'


login procedure
client sends plaintext login request 'R USERNAME'
server responds with users salt and the public key for encrypting = 'S SALT PUBLICKEY'
client sends encrypted login request 'C (USER PASS) where () is encrypted'
server responeds with 'L pass' or 'L fail'

new user procedure
client sends new user request 'N (USERNAME PASS SALT) where () is encrypted'
server responds 'N pass' or 'N fail' or 'N exits' for success, failiure, or user already exists

modify password procedure
client sends 'M USER OLDPASS NEWPASS'

sending text
client sock sends 'T text' to server
server sends 'T text' to all clients


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
UserDict = {}
DEBUG = False
SERVER = None
    
            
def broadcast(sock,message):
    #sends a message to everyone on the server
    for socket in SOCKET_LIST:
        if socket is not SERVER:# and socket is not sock:
            try:
                send_message(socket, message)
                if(DEBUG):
                    print('sent a message')
                    print(message)
            except:
                socket.close()
                if socket in SOCKET_LIST:
                    SOCKET_LIST.remove(socket)
                    
                    
def print_all_users():
    print('printing all users')
    cursor = db.execute("SELECT * from LOGINDATA")
    for row in cursor:
        print("USER = "+ row[0])
        print ("PASS = "+row[1])
        print ("SALT = "+row[2])
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
        hashed = hashlib.pbkdf2_hmac('sha256',base64.b64encode(password.encode()),binascii.unhexlify(row[2]),100000)
        if row[1] == binascii.hexlify(hashed).decode('utf-8'):
            return True
    return False

def changePass_server_side(input):
    name = input[0]
    password = input[1]
    newPassword = input[2]
    if(checkPass(name,password)):
        try:
            hashed_passed, salt = hashPassword(password)
            db.execute("""UPDATE LOGINDATA     
                SET PASS = ?,    
                    SALT = ?
                WHERE USERNAME = ?;""",((hashed_passed,salt,name,)))
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
    privateKey = importPrivateKey('privateKey.txt')
    return decrypt(message,privateKey).decode('utf-8')
    

def processMessage(message,sock):
    instruction = chr(message[0])

    if  instruction is 'R':

        #message format is login_request:name:(padding):
        parsed = message.decode('utf-8').split(' ')
        name = message[1]
        salt = str(getSalt(name))
        publicKey = importPubKey('publicKey.txt')
        key = rsa.PublicKey.save_pkcs1(publicKey)
        reply = 'S '+salt+' '
        reply = reply.encode('utf-8')+key
        send_message(sock,reply)
        return
    
    if instruction is 'C':
        #message format is C encrypted 
        try:
            decrypted = decodeMessage(message[2:]).split(' ')
            #decrypted is "name password"
            login_sucessful = checkPass(decrypted[0],decrypted[1])
            if(login_sucessful):
                send_message(sock,"L pass")
                global UserDict
                UserDict[sock] = decrypted[0]
            else:
                send_message(sock,"L fail")
        except Exception as e:
            print(e)
        return
    
    
    if instruction is 'N':
        #message format is N name password salt 
        parsed = message.decode('utf-8').split(' ')[1:]
        #parsed is now [name, pass, salt]
        if(user_is_in_database(parsed[0])):
            send_message(sock,"N exists")
        else:
            if(add_user_serverSide(parsed)):
                send_message(sock,"N pass")
            else:
                send_message(sock,"N fail")
        return
    
    if  instruction is 'T':
        #new message to transmit to all clients
        #format is T ID, Text
        message = message.decode('utf-8').split(' ',1)[1:]
        name = UserDict[sock]
        broadcast(sock,"T "+name+": "+message[0])
        
        
        pass
    
    if instruction == 'M':
        #message format is change_pass:user:oldpass:newpass
        parsed = message.decode('utf-8').split(' ')[1:]
        if(user_is_in_database(parsed[0])):
            if(changePass_server_side(message[1:])):
                send_message(sock,"changePassSucess")            
        else:
                send_message(sock,"changePassFailure")
        return
    
        
def send_message(sock,message):
    if (type(message) is bytes):
        sock.sendall(message)
    else:
        sock.sendall(message.encode('utf-8'))
    
    if(DEBUG):
        print('sending : ', end='')
        print(message)
    
    
def chat_server():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST,PORT))
        s.listen(10)
        print("Server Started on PORT {}".format(PORT))
        global SERVER
        SERVER = s
        
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
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        if(DEBUG):
                            print('recieved: ', end='')
                            print(data)
                        processMessage(data,sock)   
                        
                    else:
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)
                        broadcast(sock,"{} is offline".format(sock.address))
                except:
                    #broadcast(s,sock,"client disconnected")
                    continue
    s.close()
    

if __name__ == "__main__":
    
    sys.exit(chat_server())