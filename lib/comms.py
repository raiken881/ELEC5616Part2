import struct
from Crypto import Random
from Crypto.Random import random
import hmac
import hashlib
import base64
import datetime
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from dh import create_dh_key, calculate_dh_secret


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.keyExhangePerformed = False
        self.client = client
        self.server = server
        self.verbose = verbose
        self.shared_hash = None
        self.mac = None
        self.counter = None
        self.receivedCounter = None
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
        # TODO: Your code here!
        # This can be broken into code run just on the server or just on the client

        # To avoid random number generated on the server and the client to coincide(if it happens), we choose different
        # range of integers
        if self.server:
            self.counter = random.randint(0, 10000000)

        if self.client:
            self.counter = random.randint(11000000, 50000000)

        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_hash = calculate_dh_secret(their_public_key, my_private_key)

        self.keyExhangePerformed = True

    def send(self, data):

        # Encrypt the message along with the counter and send the computed HMAC along with the message
        # THe key for encryption is half of the shared secret and the other half is used for the HMAC generation
        # Message is sent in the form "encryptedData,HMAC!"
        if self.keyExhangePerformed:
            keyForEncryption = self.shared_hash[:int(len(self.shared_hash)/2)]
            encrypted_data = self.encryptUsingBlockCipher(data, bytes(keyForEncryption, "ascii"))
            keyForHMAC = self.shared_hash[int(len(self.shared_hash)/2) + 1 :]
            messageAuthCode = self.computeMAC(bytes(keyForHMAC, "ascii"), encrypted_data)
            encrypted_data = encrypted_data + bytes(',', "ascii") + bytes(messageAuthCode, "ascii") + bytes('!', "ascii")
            self.counter += 1

        if self.verbose:
            print("Original data: {}".format(data))
            print("Encrypted data: {}".format(repr(encrypted_data)))
            print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        # Break down the message into n messages depending on the length of the message
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):

        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]
        encrypted_data = self.conn.recv(pkt_len)

        if self.keyExhangePerformed:
            # Extract the message code and the encrypted data from the received data
            # Half of the shared secret is used for decryption and the other half for HMAC generation
            keyForDecryption = self.shared_hash[:int(len(self.shared_hash) / 2)]
            indexOfDelim = self.findDelimiter(encrypted_data, ',')
            data = encrypted_data[0:indexOfDelim]
            indexOfMessageEnd = self.findDelimiter(encrypted_data, '!')
            keyForHMAC = self.shared_hash[int(len(self.shared_hash) / 2) + 1:]
            messageAuthCode = encrypted_data[indexOfDelim + 1: indexOfMessageEnd]
            receiverMessageCode = bytes(self.computeMAC(bytes(keyForHMAC, "ascii"), data),"ascii")
            data = self.decryptMessage(data, keyForDecryption)

            # Extract the counter from the decrypted data
            indexOfDelim = self.findDelimiter(data, ',')
            delimOfPad = self.findDelimiter(data, '!')
            counter = int(data[indexOfDelim + 1:delimOfPad])
            data = data[:indexOfDelim]

            # If we are in the server then check the client's counter sent against saved counter. If the counter is less
            # Then a replay attack is being performed and we just abort the current communication
            if self.server:
                if self.receivedCounter is None:
                    self.receivedCounter = counter

                if not(self.compareCounter(counter, self.receivedCounter)):
                    print("Packet has already been seen. Good try but this packet will be rejected")
                    self.conn.close()

            if self.client:
                if self.receivedCounter is None:
                    self.receivedCounter = counter

                if not(self.compareCounter(counter, self.receivedCounter)):
                    print("Packet has already been seen. Good try but this packet will be rejected")
                    self.conn.close()

            # If HMAC differs then stop
            if not(self.compareMAC(messageAuthCode, receiverMessageCode)):
                print("MACs aren't similar. I'm going to kill the connection now... Bye!")
                self.conn.close()

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()

    # Return the computed HMAC with an output length of 32 bytes(256 bits)
    def computeMAC(self, key, message):
        MAC = HMAC.new(key,message,SHA256)
        return MAC.hexdigest()[:32]

    # If the key length is > 32 then get the first 32 bytes of the key(since the block cipher accept keys of only 32 bytes
    # long max). Create an initialisation vector which is a random byte string generated using pycrypto random function
    # Encrypt message with shared secret using block cipher in CFB mode and add the initialisation vector to it
    # Then encode the result in base 64 with a padding in case a padding error occurs
    def encryptUsingBlockCipher(self, message, key):

        if len(key) > 32:
            key = key[0:32]

        initialvector = Random.new().read(AES.block_size)
        encryptionAES = AES.new(key, AES.MODE_CBC, initialvector)
        messageToPad = message+ bytes(',',"ascii") + bytes(str(self.counter), "ascii")
        encryptedMessage = initialvector + encryptionAES.encrypt(self.padMessageToBeEncrypted(messageToPad))
        return self.padInput(base64.b64encode(encryptedMessage))


    # Same logic as the encrypter. If the key length is > 32 then take only the first 32 bytes. Since the encrypted message
    # is encoded in base 64, decode it first using the base 64 method and then use AES CFB mode block cipher to decrypt
    # the message with the initialisation vector extracted from the message.
    # NOTE: we know which one is the initialisation vector in the message as the AES.blocksize is used(16 bytes).
    def decryptMessage(self,message,secretKey):

        if len(secretKey) > 32:
            secretKey = secretKey[0:32]

        decodedMessage = base64.b64decode(message)
        initialVector = decodedMessage[:16]
        aesDecrypter = AES.new(secretKey, AES.MODE_CBC, initialVector)
        decryptMessage = aesDecrypter.decrypt(decodedMessage[16:])

        return decryptMessage

    # Find the delimiter in the given string
    def findDelimiter(self, data, delimiter):
        delimiterCode = bytes(delimiter, "ascii")[0]
        for x in range(0, len(data)):
            if data[x] == delimiterCode:
                return x

    # If the input is not a multiple of base64 acceptable length then pad it else some decoding error might occur
    def padInput(self, inputToBePadded):
        multipleOfb64 = 4
        missingBytes = len(inputToBePadded) % multipleOfb64

        if missingBytes > 0:
            for x in range(0, missingBytes):
                inputToBePadded += bytes('=', "ascii")

        else:
            for x in range(0, multipleOfb64):
                inputToBePadded += bytes('=', "ascii")

        return inputToBePadded

    # compare the hexdigest of the 2 MACS
    def compareMAC(self, senderMessageCode, recieverMessageCode):

        return senderMessageCode == recieverMessageCode

    # Compare the counters. If the counter on the receiver side is greater than the received counter then it means
    # that the packet has been replayed
    def compareCounter(self,senderCounter,receiverCounter):

        if receiverCounter > senderCounter:
            return False

        if receiverCounter < senderCounter:
            return True

        return True

    # Pad the message for CBC mode such that the message is a factor of 16 in length
    def padMessageToBeEncrypted(self,message):
        # Length of message for CBC to accept it
        multipleOfCBC = 16

        missingBytes = len(message) % multipleOfCBC
        if len(message) > multipleOfCBC:
            if missingBytes != 0:

                for x in range(0, multipleOfCBC):
                    message += bytes(str('!'), "ascii")
                    if len(message) % multipleOfCBC == 0:
                        break

        else:
            missingBytes = multipleOfCBC - missingBytes

            for x in range(0,missingBytes):
                message += bytes(str('!'), "ascii")

        return message
