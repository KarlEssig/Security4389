This project was created using Python 3.7.4

Dependencies:
pycryptodome

Use pip to install pycryptodome to remove the dependency

"pip install pycryptodome"

MAKE SURE YOU ARE USING PIP FOR PYTHON 3!!

Inputs:
aliceprivate.bin - A binary file containing alice's private RSA key
bobprivate.bin - A binary file containing bob's private RSA key
StreamCipherInput.bin - The message that Alice wants to send Bob
GenerateKeyFiles.py (OPTIONAL) - Generates a new private key for bob and alice, one can designate the names of the files that you want the keys saved to

Program Files:
Alice.py - The methods that entity alice will run in order to send a message to Bob
Bob.py - The methods that entity bob will run in order to recieve a message from Alice
RC4.py - Implementation of the RC4 Stream Cipher
Scheme.py - The MAIN program file, maintains communication between Alice.py and Bob.py

Important Outputs:
StreamCipherOutput.bin - A binary file of the ciphertext of StreamCipherInput.bin from Alice after communication has been established
BobOutput.bin - A binary file of the plaintext of StreamCipherOutput.bin that has been decoded by Bob

HOW TO RUN:

python Scheme.py -a <file name of Alice's private key> -b <file name of Bob's private key> -d <runs debug version if value = 0, else run version with files>

The default command is:

python Scheme.py -a aliceprivate.bin -b bobprivate.bin



