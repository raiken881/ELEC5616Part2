from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random

# static class which carries out the encryption and decryption of mined data and also data to be signed
# SHA-256 is used as hash function as it is collision-resistant.
# Collision-resistant hash functions are recommended by RFC3447
# This encryption mechanism will break with data greater than the maximum accepted bytes but since we are
# dealing with updates and small bytes of data being mined, the RSA will work just well
class RSAEncrypterDecrypter(object):

    # Loads the bot master public key to be used for encrytion
    # It uses the PKCS1_v1_5 scheme together with the SHA-256 collision function to prevent collisions
    @staticmethod
    def encrypt_using_master_public(data):
        public_key_encryption_file = "./PublicKeyDir.Keys/pubkeys.pem"
        h = SHA256.new(data)
        key = RSA.importKey(open(public_key_encryption_file, 'rb').read())
        cipher = PKCS1_v1_5.new(key)
        ciphertext = cipher.encrypt(data + h.digest())
        return ciphertext

    # Loads the private key only known to the bot master only to decrypt the encrypted data uploaded by the bot
    @staticmethod
    def decrypt_using_master_private(data):
        private_key_encryption_file = "./privateKeyFile/privatekey.pem"
        key = RSA.importKey(open(private_key_encryption_file, 'rb').read())

        dsize = SHA256.digest_size
        sentinel = Random.new().read(15 + dsize)
        cipher = PKCS1_v1_5.new(key)
        return cipher.decrypt(data, sentinel)

    # Loads the bot's public key and uses it for encryption of the file to be signed
    @staticmethod
    def encrypt_using_bot_public(data):
        public_key = RSA.importKey(open("../PublicKeyDir.Keys/botpubkey.pem", 'rb').read())
        h = SHA256.new(data)
        cipher = PKCS1_v1_5.new(public_key)
        ciphertext = cipher.encrypt(data + h.digest())

        return ciphertext

    # Decrypt the data in the file containing the signature if the signature has been accepted
    @staticmethod
    def decrypt_using_bot_private(data):
        private_key_encryption_file = "./lib/botPrivateKey/botprivatekey.pem"
        key = RSA.importKey(open(private_key_encryption_file, 'rb').read())
        digest_size = SHA256.digest_size
        sentinel = Random.new().read(15 + digest_size)
        cipher = PKCS1_v1_5.new(key)
        return cipher.decrypt(data, sentinel)
