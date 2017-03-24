from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

#generateKey
def generateKey():
    return RSA.generate(1024)
    


def encrypt(message,publicKey):
    #encrypt
    cipher = PKCS1_OAEP.new(publicKey)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def decrypt(ciphertext,privateKey):
    #decrypt
    cipher = PKCS1_OAEP.new(privateKey)
    message = cipher.decrypt(ciphertext)
    return message

def importKey(key):
    return RSA.importKey(open(key).read()) #key is a file

def exportKey(fileName,key,private=False):
    f = open(fileName,'w')
    if(private):
        f.write(key.exportKey('PEM'))
    else:
        f.write(key.publickey().exportKey('PEM'))
    f.close()
    