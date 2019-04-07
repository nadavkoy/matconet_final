
from Crypto.PublicKey import RSA

from Crypto.Cipher.AES import AESCipher
from Crypto.Random.random import getrandbits, randint
from Crypto import Random
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
import pickle

KEY_LENGTH = 1024


class Cryptonew:
    private_key = None
    public_key = None

    def __init__(self):
        self.private_key = RSA.generate(KEY_LENGTH)
        self.public_key = self.private_key.publickey()

    # ----------------------------------------------------------
    def get_public(self):
        return self.public_key

    def get_private(self):
        return self.private_key

    def encrypt(self, data, public_key):
        pack_data = self.pack(data)
        if not public_key:
            public_key = self.private_key.publickey()
        return public_key.encrypt(pack_data, 32)[0]

    # ----------------------------------------------------------
    def decode(self, data, private_key):
        if not private_key:
            private_key = self.private_key
        decrypt_data = private_key.decrypt(data)

        return self.unpack(decrypt_data)

    # ----------------------------------------------------------
    def unpack(self, data):
        return pickle.loads(data.decode('base64'))

    # ----------------------------------------------------------
    def pack(self, data):
        return pickle.dumps(data).encode('base64')
    # endregion

