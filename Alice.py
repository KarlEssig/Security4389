import random
import time
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import struct
from RC4 import RC4
import array
from Crypto.Hash import SHA384
#CONSTANTS HAS TO BE THE SAME AS BOB.PY
SYMMETRIC_KEY_SIZE = 16 
NONCE_SIZE = 6
BLOCK_SIZE = 65536
SHA1_SIZE = 20

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
        self.nonceAddOne()
        self.validate(timestamp, sentnonce)    
            #respond
        return plaintext
        
    def encryptRSA(self):
        message = self.convertForRSA()
        cipher_rsa = PKCS1_OAEP.new(self.recieverpublickey)
        #cipher_rsa2 = PKCS1_OAEP.new(self.key)
        
        #preciphertext = cipher_rsa.encrypt(message)
        ciphertext = cipher_rsa.encrypt(message) #signed with Alice's private key for mutual authentification
        
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
        
    def nonceAddOne(self):
        newnonce = int.from_bytes(self.nonce, byteorder = 'big') + 1
        self.nonce = struct.pack(">q", newnonce)
        self.nonce = self.nonce[2:]
    
    def startRC4(self, plaintext, outputfilename): #possibly input a filestream
        if self.communicate_flag:
            rc_cipher = RC4(self.symmetricKey)
            x = 0 #chunk number
            out_file = open(outputfilename, "wb")
            hasher = SHA384.new()
            while (x+1)* (BLOCK_SIZE - SYMMETRIC_KEY_SIZE)< len(plaintext):
                self.symmetricKey = get_random_bytes(SYMMETRIC_KEY_SIZE) # New key to be used, should this be done?
                
                message = plaintext[x*(BLOCK_SIZE-SYMMETRIC_KEY_SIZE):(x+1)*(BLOCK_SIZE-SYMMETRIC_KEY_SIZE)] + self.symmetricKey
                hasher.update(message)
                ciphertext = rc_cipher.run(message)
                ciphertext = array.array('B', ciphertext).tobytes()
                #print("Alice {0}: {1}".format(x,self.symmetricKey))
                x = x + 1
               
                out_file.write(ciphertext)
                
                rc_cipher.changeKey(self.symmetricKey)
                
            
            #self.symmetricKey = get_random_bytes(SYMMETRIC_KEY_SIZE)  #!! Don't need to have a new key at the end of the message
            message = plaintext[x*(BLOCK_SIZE-SYMMETRIC_KEY_SIZE):]
            hasher.update(message)
            ciphertext = rc_cipher.run(message)
            ciphertext = array.array('B', ciphertext).tobytes()
            
            out_file.write(ciphertext)
            out_file.write(hasher.digest())
            out_file.close()
        else:
            print("Unable to communicate")
    
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
        #print("NONCES, WHAT IT SHOULD BE: {0} \nWHAT IT IS: {1}".format(self.nonce, sentnonce))
        if (self.nonce != sentnonce):
            print("Not equal")
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
        