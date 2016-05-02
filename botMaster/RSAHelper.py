from Crypto.PublicKey import RSA
from Crypto import Random


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

    def save_bot_privatekey(self):
        privateKeyDir = open('../lib/botPrivateKey/botprivatekey.pem', 'wb')
        privateKeyDir.write(self.__RSAGenerator.exportKey())
        privateKeyDir.close()

    def save_bot_publickey(self):
        publicKeyDir = open('../PublicKeyDir.Keys/botpubkey.pem', 'wb')
        print("Public key saved is {}".format(self.__RSAGenerator.publickey()))
        publicKeyDir.write(self.__publicKey.exportKey(format='PEM'))
        publicKeyDir.close()

    def save_signature_private_key(self):
        privateKeyDir = open('./privateKeyFile/privatekeysign.pem', 'wb')
        privateKeyDir.write(self.__RSAGenerator.exportKey())
        privateKeyDir.close()

    def save_verify_public_key(self):
        publicKeyDir = open('../PublicKeyDir.Keys/pubkeyverify.pem', 'wb')
        print("Public key saved is {}".format(self.__RSAGenerator.publickey()))
        publicKeyDir.write(self.__publicKey.exportKey(format='PEM'))
        publicKeyDir.close()









