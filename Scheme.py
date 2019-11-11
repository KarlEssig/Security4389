#STEP 1, create ALICE and BOB and give them their respective keys
#STEP 2, Alice wants to communicate with Bob, gets Bobs public key for RSA
#STEP 3, Alice creates the message they want to send to bob and encrypts it using RSA

from Crypto.PublicKey import RSA
from Alice import Alice
from Bob import Bob
from optparse import OptionParser
#GLOBALS
RSA_KEY_SIZE = 2048


def main():
    global RSA_KEY_SIZE
    usage = "usage: %prog [options] arg"
    parser = OptionParser()

    parser.add_option("-a", "--aliceprivate", action="store", dest="alicekeyfile",help="The file where Alice's key has been stored", default = None)
    parser.add_option("-b", "--bobprivate", dest="bobkeyfile", default = None)
    parser.add_option("-c", "--alicepublic", action="store", dest="alicepublic",help="The file where Alice's key has been stored", default = None)
    parser.add_option("-d", "--bobpublic", dest="bobpublic", default = None)
    #parser.add_option("-p", "--httpPortIndex", type="int",dest="httpPortIndex", default=1200)
    #parser.add_option("-s", "--streamPortIndex", type="int",dest="streamPortIndex", default=5000)
    (options, args) = parser.parse_args()
    alicekey = None
    bobkey = None
    print("Starting alice's key")
    if options.alicekeyfile is None: #generate a key for RSA
        alicekey = RSA.generate(RSA_KEY_SIZE)
    else:
        alicefile = open(options.alicekeyfile, "rb").read()
        alicekey = RSA.import_key(alicefile)
        #alicepublic = alicekey.publickey()
        #print(alicepublic.export_key())
        #print(alicekey)
    print("Starting bob's key")    
    if options.bobkeyfile is None: #generate a key pair for RSA
        bobkey = RSA. generate(RSA_KEY_SIZE)
    else:
        bobfile = open(options.bobkeyfile, "rb").read()
        bobkey = RSA.import_key(bobfile)
        #bobpublic = alicekey
    
    
    alice = Alice(alicekey)
    bob = Bob(bobkey)
    alice.setRecieverPublic(bobkey.publickey())
    bob.setSenderPublic(alicekey.publickey())
    
    print("MESSAGE PLAINTEXT - ALICE")
    print(alice.convertForRSA())
    
    print("MESSAGE CIPHERTEXT - ALICE")
    ciphertext = alice.encryptRSA()
    print(ciphertext)
    
    plaintext = bob.decryptRSA(ciphertext)
    print("MESSAGE PLAINTEXT - BOB")
    print(plaintext)
    
    ciphertext = bob.encryptRSA()
    print("MESSAGE CIPHERTEXT - BOB")
    print(ciphertext)
    
    plaintext = alice.decryptRSA(ciphertext)
    print("MESSAGE PLAINTEXT - ALICE")
    print(plaintext)
    
    print("START SYMMETRIC ENCRYPTION")
    inputplaintext = open("StreamCipherInput.bin", "rb")
    plaintext = inputplaintext.read()
    alice.startRC4(plaintext, "StreamCipherOutput.bin")
    inputplaintext.close()
    
    print("BOB DECODE")
    inputciphertext = open("StreamCipherOutput.bin", "rb")
    ciphertext = inputciphertext.read()
    bob.startRC4(ciphertext, "BobOutput.bin")
    inputciphertext.close()
    
    

if __name__ == '__main__':
    main()