from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS


class RSAHelper(object):
    __publicKey = 0
    __RSAGenerator = 0

    def __init__(self):
        self.initiatePublicKeyProtocol()

    def initiatePublicKeyProtocol(self):
        minBitsRequired = 4096
        generate_random = Random.new().read
        self.setRSAGenerator(RSA.generate(minBitsRequired,generate_random))
        self.setPublicKey(self.__RSAGenerator.publickey())

    def setRSAGenerator(self,generator):
        self.__RSAGenerator = generator

    def getRSAGenerator(self):
        return self.__RSAGenerator

    def setPublicKey(self,publicKey):
        self.__publicKey = publicKey

    def getPublicKey(self):
        return self.__publicKey

    def sign(self,message):
        hashFunction = SHA256.new()
        hashFunction.update(message)
        private_key_file = open('./privateKeyFile/privateKey.pem','rb')
        rsa_private_key = RSA.importKey(private_key_file.read())
        signer = PKCS1_PSS.new(rsa_private_key)
        return signer.sign(hashFunction)

    # Used only once to generate a valid public-private key pair
    def savePubKey(self):
        publicKeyDir = open('../PublicKeyDir.Keys/pubkeys.pem','wb')
        print("Public key saved is {}".format(self.__RSAGenerator.publickey()))
        publicKeyDir.write(self.__publicKey.exportKey(format='PEM'))
        publicKeyDir.close()

    def savePriKey(self):
        privateKeyDir = open('./privateKeyFile/privateKey.pem','wb')
        privateKeyDir.write(self.__RSAGenerator.exportKey())
        privateKeyDir.close()


    def verifySignature(self,message,signature):
        public_key_dir = open('../PublicKeyDir.Keys/pubkeys.pem','rb')
        public_key = RSA.importKey(public_key_dir.read())
        verifier = PKCS1_PSS.new(public_key)
        hash_message = SHA256.new(message)

        if verifier.verify(hash_message,signature):
            return True

        else:
            return False







