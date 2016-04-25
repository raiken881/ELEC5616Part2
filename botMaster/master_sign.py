import os
from botMaster.SigningHelper import SigningHelper

def sign_file(f):
    signingHelper = SigningHelper()
    signature = signingHelper.sign(f)
    print("Message has been signed result is {}".format(signature))
    signingHelper.savePubKey()
    return signature

def saveFile(filepath,file):
    signed_fn = os.path.join("../pastebot.net", filepath + ".signed")
    out = open(signed_fn, "wb")
    out.write(file)
    out.close()

if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("../pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("../pastebot.net", fn), "rb").read()
    saveFile(fn,f)
    signed_f = sign_file(f)
    out = open("../Signatures/signature", "wb")
    out.write(signed_f)
    out.close()
    # print("Signed file written to", out.)

# Bot master generates a public/private key pair
# Bot master signs the message to be sent with its own private key
# The receiver will generate a hash of the message and use the signature for verification