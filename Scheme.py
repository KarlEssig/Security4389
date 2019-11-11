#STEP 1, create ALICE and BOB and give them their respective keys
#STEP 2, Alice wants to communicate with Bob, gets Bobs public key for RSA
#STEP 3, Alice creates the message they want to send to bob and encrypts it using RSA

from Crypto.PublicKey import RSA
from Alice import Alice
from Bob import Bob
from optparse import OptionParser
#GLOBALS
RSA_KEY_SIZE = 2048
INITIAL_MESSAGE_FILE = "StreamCipherInput.bin"
SHARED_MESSAGE_FILE = "StreamCipherOutput.bin"
BOB_OUTPUT_FILE = "BobOutput.bin"


def main(options):
    global RSA_KEY_SIZE, INITIAL_MESSAGE_FILE, SHARED_MESSAGE_FILE, BOB_OUTPUT_FILE
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
    inputplaintext = open(INITIAL_MESSAGE_FILE, "rb")
    plaintext = inputplaintext.read()
    alice.startRC4(plaintext, SHARED_MESSAGE_FILE)
    inputplaintext.close()
    
    print("BOB DECODE")
    inputciphertext = open(SHARED_MESSAGE_FILE, "rb")
    ciphertext = inputciphertext.read()
    bob.startRC4(ciphertext, BOB_OUTPUT_FILE)
    inputciphertext.close()
    
def demo(options):
    global RSA_KEY_SIZE, INITIAL_MESSAGE_FILE, SHARED_MESSAGE_FILE, BOB_OUTPUT_FILE
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
        bobkey = RSA.generate(RSA_KEY_SIZE)
    else:
        bobfile = open(options.bobkeyfile, "rb").read()
        bobkey = RSA.import_key(bobfile)
        #bobpublic = alicekey
    
    
    alice = Alice(alicekey)
    bob = Bob(bobkey)
    alice.setRecieverPublic(bobkey.publickey())
    bob.setSenderPublic(alicekey.publickey())
    
    firstAlice = "aliceMessagePlaintext.bin"
    print("MESSAGE PLAINTEXT - ALICE WRITTEN TO {0}".format(firstAlice))
    message = alice.convertForRSA()
    firstAliceFile = open(firstAlice, "wb")
    firstAliceFile.write(message)
    firstAliceFile.close()
    print("Press any key to proceed")
    input()
    
    secondAlice = "aliceMessageCiphertext.bin"
    print("MESSAGE CIPHERTEXT - ALICE WRITTEN TO {0}".format(secondAlice))
    ciphertext = alice.encryptRSA()
    secondAliceFile = open(secondAlice, "wb")
    secondAliceFile.write(ciphertext)
    secondAliceFile.close()
    print("Press any key to proceed")
    input()
    
    firstBob = "bobMessagePlaintext.bin"
    print("MESSAGE PLAINTEXT - BOB WRITTEN TO {0}".format(firstBob))
    plaintext = bob.decryptRSA(ciphertext)
    firstBobFile = open(firstBob, "wb")
    firstBobFile.write(plaintext)
    firstBobFile.close()
    print("Press any key to proceed")
    input()
    
    secondBob = "bobMessageCiphertext.bin"      
    print("MESSAGE CIPHERTEXT - BOB WRITTEN TO {0}".format(secondBob))
    ciphertext = bob.encryptRSA()
    secondBobFile = open(secondBob, "wb")
    secondBobFile.write(ciphertext)
    secondBobFile.close()
    print("Press any key to proceed")
    input()
    
    
    thirdAlice = "aliceMessagePlaintext2.bin"
    print("MESSAGE PLAINTEXT - ALICE WRITTEN TO {0}".format(thirdAlice))
    plaintext = alice.decryptRSA(ciphertext)
    thirdAliceFile = open(thirdAlice, "wb")
    thirdAliceFile.write(plaintext)
    thirdAliceFile.close()
    print("Press any key to proceed")
    input()
    

    
    print("START SYMMETRIC ENCRYPTION")
    inputplaintext = open(INITIAL_MESSAGE_FILE, "rb")
    plaintext = inputplaintext.read()
    alice.startRC4(plaintext, SHARED_MESSAGE_FILE)
    inputplaintext.close()
    
    print("BOB DECODE")
    inputciphertext = open(SHARED_MESSAGE_FILE, "rb")
    ciphertext = inputciphertext.read()
    bob.startRC4(ciphertext, BOB_OUTPUT_FILE)
    inputciphertext.close()
    
        

if __name__ == '__main__':
    usage = "usage: %prog [options] arg"
    parser = OptionParser()

    parser.add_option("-a", "--aliceprivate", action="store", dest="alicekeyfile",help="The file where Alice's key has been stored", default = None)
    parser.add_option("-b", "--bobprivate", dest="bobkeyfile", default = None)
    parser.add_option("-c", "--alicepublic", action="store", dest="alicepublic",help="The file where Alice's key has been stored", default = None)
    parser.add_option("-d", "--bobpublic", dest="bobpublic", default = None)
    parser.add_option("--demo", type="int", dest="demo", help="Whether this is running the demo or not", default = 0)
    #parser.add_option("-p", "--httpPortIndex", type="int",dest="httpPortIndex", default=1200)
    #parser.add_option("-s", "--streamPortIndex", type="int",dest="streamPortIndex", default=5000)
    (options, args) = parser.parse_args()
    if options.demo == 0:
        print("Running debug version")
        main(options)
    else:
        print("Running demo version")
        demo(options)