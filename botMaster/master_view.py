import os
from botMaster.RSAEncrypterDecrypter import RSAEncrypterDecrypter
from Crypto.Hash import SHA256

def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out

    message = RSAEncrypterDecrypter().decrypt_using_master_private(f)
    digest_size = SHA256.digest_size
    digest = SHA256.new(message[:-digest_size]).digest()

    if digest == message[-digest_size:]:
        print("Encryption was correct")
    else:
        print("Encryption was not correct")

    print(message[:-digest_size])


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("../pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("../pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
