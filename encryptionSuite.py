import rsa
import os
import binascii
import hashlib
import base64

instructionDict= {
    
    }

#generateKey
def generateKey():
    #returns (pubkey, privkey)
    return rsa.newkeys(1024)
    

def encrypt(message,publicKey):
    #encrypt
    ciphertext = rsa.encrypt(message.encode(), publicKey)
    return ciphertext #bytes

def decrypt(ciphertext,privateKey):
    #decrypt
    message = rsa.decrypt(ciphertext, privateKey)
    return message #bytes

def importPrivateKey(fileName):
    with open(fileName,'rb') as privatefile:
        keydata = privatefile.read()
    return rsa.PrivateKey.load_pkcs1(keydata)
    
def importPubKey(fileName):
    with open(fileName,'rb') as privatefile:
        keydata = privatefile.read()
    return rsa.PublicKey.load_pkcs1(keydata)

def exportPriv(fileName,key):
    f = open(fileName,'wb')
    f.write(rsa.PrivateKey.save_pkcs1(key))
    f.close()
    
def exportPub(fileName,key):
    f = open(fileName,'wb')
    f.write(rsa.PublicKey.save_pkcs1(key))
    f.close()

    
def hashPassword(password):
    #returns an array containing a hashed password and the salt used
    salt = os.urandom(16)
    password = base64.b64encode(password.encode())

    hashed_pass = hashlib.pbkdf2_hmac('sha256',password,salt,100000)
    hashed_pass = binascii.hexlify(hashed_pass)
    salt = binascii.hexlify(salt)
    return hashed_pass.decode(),salt.decode()

"""
(mypub, mypriv) = generateKey()
exportPriv('privateKey.txt',mypriv)
exportPriv('publicKey.txt',mypub)
"""