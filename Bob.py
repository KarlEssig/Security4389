from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import time
import struct
#CONSTANTS
SYMMETRIC_KEY_SIZE = 16
NONCE_SIZE = 6

class Bob():
    def __init__(self, rsaKeyObject):
        self.key = rsaKeyObject
        self.symmetricKey = None
        self.senderpublickey = None
        self.nonce = None
        self.communicate_flag = True
    
    def decryptRSA(self, ciphertext):
        #cipher_rsa2 = PKCS1_OAEP.new(self.senderpublickey)
        cipher_rsa = PKCS1_OAEP.new(self.key)
        #preciphertext = cipher_rsa2.decrypt(ciphertext)
        plaintext = cipher_rsa.decrypt(ciphertext)
        self.nonce = plaintext[:NONCE_SIZE]
        self.symmetricKey = plaintext[NONCE_SIZE:SYMMETRIC_KEY_SIZE+NONCE_SIZE]
        timestamp = plaintext[SYMMETRIC_KEY_SIZE+NONCE_SIZE:]
        self.validate(timestamp)    
        return plaintext
            
    
    def encryptRSA(self):
        if self.communicate_flag:
            self.nonce = self.nonce + 1
            timestamp = self.generateTimeStamp()
            message = self.nonce + self.symmetricKey + timestamp
            cipher_rsa = PKCS1_OAEP.new(self.senderpublickey)
            #cipher_rsa2 = PKCS1_OAEP.new(self.key)
            #preciphertext = cipher_rsa.encrypt(message)#For mutual authentication
            ciphertext = cipher_rsa2.encrypt(message)  
            return ciphertext
        return -1
        
    def generateTimeStamp(self):
        k = int(time.time())
        bytetime = struct.pack(">i", k)
        return bytetime    
        
    def setSenderPublic(self, publickey):
        self.senderpublickey = publickey
        
    def toString(self):
        s = "BOB INFO\nNONCE: {0}\nSYMMETRIC KEY {1}\n".format(self.nonce, self.symmetricKey)
        return s
        
    def validate(self, sentstamp):
        currtime = int(time.time())
        currbyte = struct.pack(">i", currtime)
        difftime = [0] * 4
        for x in range(4):
            difftime[x] = currbyte[x] - sentstamp[x]
        
        if difftime[0] & 0xFF or difftime[1] & 0xFF or difftime[2] & 0xFF or difftime[3]  > 16:
            print("Could not validate timestamp")
            self.communicate_flag = False
        
            
    
   
            
    
    
        