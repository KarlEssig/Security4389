import random

class RC4():
    def __init__(self, key, plaintext = None,ciphertext = None):
        self.keysize = 256 #nice
        self.key = key
        if plaintext is not None:
            self.plaintext = plaintext
            #if ciphertext is None:
             #   self.ciphertext = [0] * len(plaintext)
        if ciphertext is not None:
            self.ciphertext = ciphertext
        self.s = [0] * self.keysize
        #self.KSA() #computes S
        
        
    def KSA(self): #depends upon keysize, key, and the s cipher, generates s cipher.
        j = 0
        leng = len(self.key)
        for x in range(0,self.keysize):
            self.s[x] = x
        
        for i in range(0, self.keysize):
            j = (j + self.s[i] + self.key[i % leng]) % self.keysize
            temp = self.s[i]
            self.s[i] = self.s[j]
            self.s[j] = temp

    
    def PRGA(self):
        self.ciphertext = [0] * len(self.plaintext)
        i = 0
        j = 0
        leng = len(self.plaintext)
        for x in range(leng):
            i = (i + 1) % self.keysize
            j = (j + self.s[i]) % self.keysize
            
            
            temp = self.s[i]
            self.s[i] = self.s[j]
            self.s[j] = temp
            
            rnd = self.s[(self.s[i] + self.s[j]) % self.keysize]
            
            self.ciphertext[x] = rnd ^ self.plaintext[x]
    
    def run(self, plaintext = None):
        if plaintext is None:
            if self.plaintext is None:
                print("Nothing to decode")
            else:
                self.KSA()
                self.PRGA()
                return self.getCiphertext()
        else:
            #print("I'm changing plaintext")
            self.plaintext = plaintext
            self.KSA()
            self.PRGA()
            return self.getCiphertext()
    
    def getCiphertext(self):
        return self.ciphertext
    
    def changeKey(self, key):
        self.key = key
        #self.KSA()
        
    def toString(self):
        print("INFO ON RC4\nKEY = {0}\nCIPHERTEXT = {1}\nPLAINTEXT = {2}\nSARRAY = {3}".format(self.key, self.ciphertext, self.plaintext, self.s))
        

if __name__ == '__main__':
    #sequence = [i for i in range(0, 256)]
    plaintext = [i for i in range(0,256 )]
    ciphertext = [0] * 256
    key = list()
    #print("PLAINTEXT: {0}".format(str(plaintext)))
    for _ in range(0, 255):
        selection = random.randint(0,255)
        key.append(selection)
    #print ("KEY: {0}".format(str(key)))
    k = RC4(key, plaintext, ciphertext)
    k.toString()
    ciphertext = k.run()
    k.toString()
    #print("CIPHERTEXT: {0}".format(str(ciphertext)))
    print("_____________GET BACK INFO_______________________")
    
    plaintext = k.run(ciphertext)
    k.toString()
    print("PLAINTEXT: {0}".format(str(plaintext)))
    