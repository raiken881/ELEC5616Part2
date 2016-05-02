import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random


class RSAEncrypterDecrypter(object):

    @staticmethod
    def encrypt_using_master_public(data):
        public_key_encryption_file = "./PublicKeyDir.Keys/pubkeys.pem"
        h = SHA256.new(data)
        key = RSA.importKey(open(public_key_encryption_file, 'rb').read())
        cipher = PKCS1_v1_5.new(key)
        ciphertext = cipher.encrypt(data + h.digest())
        return ciphertext

    @staticmethod
    def decrypt_using_master_private(data):
        private_key_encryption_file = "./privateKeyFile/privatekey.pem"
        key = RSA.importKey(open(private_key_encryption_file, 'rb').read())

        dsize = SHA256.digest_size
        sentinel = Random.new().read(15 + dsize)
        cipher = PKCS1_v1_5.new(key)
        return cipher.decrypt(data, sentinel)

    @staticmethod
    def encrypt_using_bot_public(data):
        public_key = RSA.importKey(open("../PublicKeyDir.Keys/botpubkey.pem", 'rb').read())
        h = SHA256.new(data)
        cipher = PKCS1_v1_5.new(public_key)
        ciphertext = cipher.encrypt(data + h.digest())

        return ciphertext

    @staticmethod
    def decrypt_using_bot_private(data):
        private_key_encryption_file = "./lib/botPrivateKey/botprivatekey.pem"
        key = RSA.importKey(open(private_key_encryption_file, 'rb').read())
        digest_size = SHA256.digest_size
        sentinel = Random.new().read(15 + digest_size)
        cipher = PKCS1_v1_5.new(key)
        return cipher.decrypt(data, sentinel)
