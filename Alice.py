import random
import time
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import struct
#CONSTANTS
SYMMETRIC_KEY_SIZE = 16
NONCE_SIZE = 6

class Alice():
    def __init__(self, rsaKeyObject):
        global NONCE_SIZE, SYMMETRIC_KEY_SIZE
        self.nonce = get_random_bytes(NONCE_SIZE)#self.generateNonce()
        self.timestamp = self.generateTimeStamp()
        self.symmetricKey = get_random_bytes(SYMMETRIC_KEY_SIZE)#self.generateSymmetricKey()
        self.key = rsaKeyObject
        self.recieverpublickey = None
        self.communicate_flag = True
    
    
    def convertForRSA(self):
        message = self.nonce + self.symmetricKey + self.timestamp
        return message
    
    def decryptRSA(self, ciphertext):
        #cipher_rsa2 = PKCS1_OAEP.new(self.recieverpublickey)
        cipher_rsa = PKCS1_OAEP.new(self.key)
        #preciphertext = cipher_rsa2.decrypt(ciphertext)
        plaintext = cipher_rsa.decrypt(ciphertext)
        sentnonce = plaintext[:NONCE_SIZE]
        self.symmetricKey = plaintext[NONCE_SIZE:SYMMETRIC_KEY_SIZE+NONCE_SIZE]
        timestamp = plaintext[SYMMETRIC_KEY_SIZE+NONCE_SIZE:]
        self.validate(timestamp, sentnonce)    
            #respond
        return plaintext
        
    def encryptRSA(self):
        message = self.convertForRSA()
        cipher_rsa = PKCS1_OAEP.new(self.recieverpublickey)
        #cipher_rsa2 = PKCS1_OAEP.new(self.key)
        
        #preciphertext = cipher_rsa.encrypt(message)
        ciphertext = cipher_rsa2.encrypt(message) #signed with Alice's private key for mutual authentification
        
        return ciphertext
        
    def generateNonce(self): #generates a 6 byte nonce
        global NONCE_SIZE
        nonce = [0] * NONCE_SIZE
        for i in range(0,NONCE_SIZE):
            selection = random.randint(0,255)
            nonce[i] = selection
        return nonce
    
    def generateTimeStamp(self):
        k = int(time.time())
        bytetime = struct.pack(">i", k)
        return bytetime
        
    def generateSymmetricKey(self):
        global SYMMETRIC_KEY_SIZE
        symmetricKey = [0] * SYMMETRIC_KEY_SIZE
        for i in range(0, SYMMETRIC_KEY_SIZE):
            selection = random.randint(0,255)
            symmetricKey[i] = selection
        return symmetricKey
        
    def setRecieverPublic(self, publickey):
        self.recieverpublickey = publickey
        
    def toString(self):
        s = "Alice Info\nNONCE: {0}\nTIMESTAMP {1}\nSYMMETRIC KEY {2}\nBOB'S PUBLIC KEY {3}".format(self.nonce, self.timestamp, self.symmetricKey, self.recieverpublickey.export_key())
        return s
    
    def validate(self, sentstamp, sentnonce):
        currtime = int(time.time())
        currbyte = struct.pack(">i", currtime)
        difftime = [0] * 4
        for x in range(4):
            difftime[x] = currbyte[x] - sentstamp[x]

        if difftime[0] & 0xFF or difftime[1] & 0xFF or difftime[2] & 0xFF or difftime[3]  > 16:
            print("Could not validate timestamp")
            self.communicate_flag = False
        if (self.nonce + 1 != sentnonce):
            self.communicate_flag = False
        
if __name__ == '__main__':
    k = get_random_bytes(6)
    #print(k)
    #print(k[3:])
    a = int(time.time())
    print(a)
    bytetime = struct.pack(">i", a)
    print(bytetime)
    w = k + bytetime
    print(w)
    time.sleep(3)
    b = int(time.time()+8192)
    bytetime2 = struct.pack(">i", b)
    print(bytetime2)
    huh1 = bytetime2[0] - bytetime[0]
    huh2 = bytetime2[1] - bytetime[1]
    huh3 = bytetime2[2] - bytetime[2]
    huh4 = bytetime2[3] - bytetime[3]
    print("0: {0} 1: {1} 2: {2} 3: {3}".format(huh1, huh2, huh3, huh4))
    if huh1 & 0xFF or huh2 & 0xFF or huh3 & 0xFF or huh4  > 16:
            print("Could not validate timestamp")
    #print(w[5:])
    #print(k[3:])
    #print(int(k[4]))
        