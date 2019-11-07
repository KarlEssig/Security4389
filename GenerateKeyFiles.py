from Crypto.PublicKey import RSA 
from optparse import OptionParser
#Run this program if the keys for alice/bob haven't been generated in a file

def main():
    usage = "usage: %prog [options] arg"
    parser = OptionParser()

    parser.add_option("-a", "--aliceprivate", action="store", dest="aliceprivate",help="The name of the file where Alice's key has to be stored", default = "aliceprivate.bin")
    parser.add_option("-b", "--bobprivate", dest="bobprivate", default = "bobprivate.bin")
    parser.add_option("-c", "--alicepublic", action="store", dest="alicepublic",help="The file where Alice's public key has been stored", default = "alicepublic.bin")
    parser.add_option("-d", "--bobpublic", dest="bobpublic", default = "bobpublic.bin")
    #parser.add_option("-p", "--httpPortIndex", type="int",dest="httpPortIndex", default=1200)
    #parser.add_option("-s", "--streamPortIndex", type="int",dest="streamPortIndex", default=5000)
    (options, args) = parser.parse_args()
    
    print("generating alice's key")
    alicekey = RSA.generate(2048)
    alice_key = alicekey.export_key()
    alice_public = alicekey.publickey().export_key()
    alice_private_file = open(options.aliceprivate, "wb")
    alice_private_file.write(alice_key)
    alice_public_file = open(options.alicepublic, "wb")
    alice_public_file.write(alice_public)
    alice_private_file.close()
    alice_public_file.close()
    
    print("generating bob's key")
    bobkey = RSA.generate(2048)
    bob_key = bobkey.export_key()
    bob_public = bobkey.publickey().export_key()
    bob_private_file = open(options.bobprivate, "wb")
    bob_private_file.write(bob_key)
    bob_public_file = open(options.bobpublic, "wb")
    bob_public_file.write(bob_public)
    bob_private_file.close()
    bob_public_file.close()
    print("Done")
    
if __name__ == "__main__":
    main()
