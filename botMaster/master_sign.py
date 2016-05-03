import os
from botMaster.RSASignVerify import RSASignAndVerify
from botMaster.RSAEncrypterDecrypter import RSAEncrypterDecrypter

# We are using an encrypt-then-sign mechanism where the file is encrypted then
# the resultant is fed to the signature function
def sign_file(f):
    ciphertext = RSAEncrypterDecrypter().encrypt_using_bot_public(f)
    master_signature = RSASignAndVerify().sign_file(ciphertext)
    return master_signature + ciphertext


if __name__ == "__main__":
    if __name__ == "__main__":
        fn = input("Which file in pastebot.net should be signed? ")
        if not os.path.exists(os.path.join("../pastebot.net", fn)):
            print("The given file doesn't exist on pastebot.net")
            os.exit(1)
        f = open(os.path.join("../pastebot.net", fn), "rb").read()
        signed_f = sign_file(f)
        signed_fn = os.path.join("../pastebot.net", fn + ".signed")
        out = open(signed_fn, "wb")
        out.write(signed_f)
        out.close()
