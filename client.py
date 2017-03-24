import socket
class client:

    def __init__(self,sock,name,salt,key):
        self.socket = sock
        self.name = name
        self.salt = salt
        self.key = key