import os
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.PublicKey import  RSA
from Crypto.Cipher import PKCS1_v1_5

def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out
    key = RSA.importKey(open('privateKeyFile/privatekey.pem', 'rb').read())

    dsize = SHA.digest_size
    sentinel = Random.new().read(15+dsize)
    cipher = PKCS1_v1_5.new(key)
    message = cipher.decrypt(f, sentinel)

    digest = SHA.new(message[:-dsize]).digest()
    
    if digest == message[-dsize:]:
        print("Encryption was correct")
    else:
        print ("Encryption was not correct")

    print(message[:-dsize])


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("../pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("../pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
