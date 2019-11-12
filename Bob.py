from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import time
import struct
from RC4 import RC4
import array
from Crypto.Hash import SHA384
#CONSTANTS HAS TO BE THE SAME AS ALICE.PY
SYMMETRIC_KEY_SIZE = 16 
NONCE_SIZE = 6
BLOCK_SIZE = 65536
SHA384_SIZE = 48

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
            self.nonceAddOne()
            timestamp = self.generateTimeStamp()
            message = self.nonce + self.symmetricKey + timestamp
            #print(message)
            cipher_rsa = PKCS1_OAEP.new(self.senderpublickey)
            ciphertext = cipher_rsa.encrypt(message)  
            return ciphertext
        return -1
        
    def generateTimeStamp(self):
        k = int(time.time())
        bytetime = struct.pack(">i", k)
        return bytetime

    def nonceAddOne(self):
        newnonce = int.from_bytes(self.nonce, byteorder = 'big') + 1
        self.nonce = struct.pack(">q", newnonce)
        self.nonce = self.nonce[2:]
        
    def setSenderPublic(self, publickey):
        self.senderpublickey = publickey
        
    def startRC4(self, plaintext, outputfilename): #possibly input a filestream
        #print("PLAINTEXT OF STREAM: {0}".format(plaintext))
        if self.communicate_flag:
            rc_cipher = RC4(self.symmetricKey)
            x = 0 #chunk number
            out_file = open(outputfilename, "wb")
            hasher = SHA384.new()
            while (x+1)* BLOCK_SIZE< len(plaintext):
                
                ciphertext = rc_cipher.run(plaintext[x*BLOCK_SIZE:(x+1)*BLOCK_SIZE])
                ciphertext = array.array('B', ciphertext).tobytes() #last 6 bytes will be new key
                hasher.update(ciphertext)
                self.symmetricKey = ciphertext[len(ciphertext)-SYMMETRIC_KEY_SIZE:] 
                print("Bob {0}: {1}".format(x,self.symmetricKey))
                x = x + 1
                #print("CIPHERTEXT OF STREAM: {0}".format(ciphertext))
                out_file.write(ciphertext)
                rc_cipher.changeKey(self.symmetricKey)
                #hash ciphertext?
                #change key?
            
            ciphertext = rc_cipher.run(plaintext[x*BLOCK_SIZE: len(plaintext) - SHA384_SIZE]) #is -1 correct?
            ciphertext = array.array('B', ciphertext).tobytes()
            hasher.update(ciphertext)
            endhash = plaintext[len(plaintext) - SHA384_SIZE:]
            print("THIS HASHES DIGEST {0}".format(hasher.digest()))
            print("DIGEST OF ALICE'S HASH {0}".format(endhash))
            
            #print("RC4 CIPHERTEXT: {0}".format(ciphertext))
            out_file.write(ciphertext)
            out_file.close()
        else:
            print("Unable to communicate")
        
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
        
            
    
   
            
    
    
        