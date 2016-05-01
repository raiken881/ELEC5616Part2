import os
from botMaster.RSASignVerify import RSASignAndVerify


def sign_file(f):
    master_signature = RSASignAndVerify().sign_file(f)
    end_signature = bytes('===\n', "ascii")
    return master_signature + end_signature + f


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
