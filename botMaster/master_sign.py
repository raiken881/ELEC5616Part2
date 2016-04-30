import os
from botMaster.RSASignVerify import RSASignAndVerify


def sign_file(f):
    master_signature = RSASignAndVerify().sign_file(f)
    new_line = bytes('\n', "ascii")
    end_signature = bytes('END', "ascii")
    return master_signature + end_signature + new_line + f


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

        signed_file = open('../pastebot.net/hello.fbi.signed','rb')

        signature = b''
        content = b''
        delimiterFound = False
        for line in signed_file:

            if line == b'\n':
                delimiterFound = True
                continue

            if delimiterFound:
                content += line

            if not delimiterFound:
                signature += line

        print("signature is {}".format(signature))
        print("content is {}".format(content))



        signed_file.close()


        print("Signed file written to", signed_fn)

# Bot master generates a public/private key pair
# Bot master signs the message to be sent with its own private key
# The receiver will generate a hash of the message and use the signature for verification