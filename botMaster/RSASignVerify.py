from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS

# This static class makes use of the PKCS1_PSS object to provide an easy and secure mechanism
# to sign and verfiy signatures
class RSASignAndVerify(object):

    @staticmethod
    def sign_file(message):
        hashed_message = SHA256.new(message)
        private_key_file = open('./privateKeyFile/privatekeysign.pem', 'rb')
        rsa_private_key = RSA.importKey(private_key_file.read())
        signer = PKCS1_PSS.new(rsa_private_key)
        return signer.sign(hashed_message)

    @staticmethod
    def verify_signature(message,signature):
        public_key_dir = open('PublicKeyDir.Keys/pubkeyverify.pem', 'rb')
        public_key = RSA.importKey(public_key_dir.read())
        verifier = PKCS1_PSS.new(public_key)
        hash_message = SHA256.new(message)

        if verifier.verify(hash_message, signature):
            return True

        else:
            return False
