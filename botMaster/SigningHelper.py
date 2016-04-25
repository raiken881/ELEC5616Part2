from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS


class SigningHelper(object):
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
        signer = PKCS1_PSS.new(self.__RSAGenerator)
        return signer.sign(hashFunction)

    def savePubKey(self):
        publicKeyDir = open('../PublicKeyDir.Keys/pubkeys.pem','wb')
        print("Public key saved is {}".format(self.__RSAGenerator.publickey()))
        publicKeyDir.write(self.__publicKey.exportKey(format='PEM'))
        publicKeyDir.close()





