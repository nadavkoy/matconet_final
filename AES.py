
from Crypto.Cipher import AES
from base64 import b64encode
from base64 import b64decode
import sys


BLOCK_SIZE = 16

# Your input has to fit into a block of BLOCK_SIZE.
# To make sure the last block to encrypt fits in the block, you may need to pad the input.
# This padding must later be removed after decryption so a standard padding would help.
# The idea is to separate the padding into two concerns: interrupt and then pad
# First you insert an interrupt character and then a padding character
# On decryption, first you remove the padding character until you reach the interrupt character
# and then you remove the interrupt character
INTERRUPT = u'\u0001'
PAD = u'\u0000'


class AESCrypt(object):
    # Strip your data after decryption (with pad and interrupt_
    def StripPadding(self, data):
        return data.rstrip(PAD).rstrip(INTERRUPT)

    # Decrypt the given encrypted data with the decryption cypher
    def DecryptWithAES(self, decrypt_cipher, encrypted_data):
        decoded_encrypted_data = b64decode(encrypted_data)
        decrypted_data = decrypt_cipher.decrypt(decoded_encrypted_data)
        return self.StripPadding(decrypted_data)

    # Pad your data before encryption (with pad and interrupt_
    def AddPadding(self, data):
        new_data = ''.join([data, INTERRUPT])
        new_data_len = len(new_data)
        remaining_len = BLOCK_SIZE - new_data_len
        to_pad_len = remaining_len % BLOCK_SIZE
        pad_string = PAD * to_pad_len
        return ''.join([new_data, pad_string])

    # Encrypt the given data with the encryption cypher
    def EncryptWithAES(self, encrypt_cipher, plaintext_data):
        plaintext_padded = self.AddPadding(plaintext_data)
        encrypted = encrypt_cipher.encrypt(plaintext_padded)
        return b64encode(encrypted)

    def encryptAES(self, secretKEY, data_to_encrypt):
        try:
            # Let's create our encryption & decryption cipher objects
            encryption_cypher = AES.new(secretKEY)

            # We are now ready to encrypt and decrypt our data
            encrypted_data = self.EncryptWithAES(encryption_cypher, data_to_encrypt)
            return encrypted_data

        # Catch any general exception
        except Exception, err:
            print >> sys.stderr, err.message
            print >> sys.stderr, "for help use --help"
            return None

    def decryptAES(self, secretKEY, encrypted_data):
        try:
            # Let's create our encryption & decryption cipher objects
            decryption_cypher = AES.new(secretKEY)

            #  And let's decrypt our data
            decrypted_data = self.DecryptWithAES(decryption_cypher, encrypted_data)
            return decrypted_data

        # Catch any general exception
        except Exception, err:
            print >> sys.stderr, err.message
            print >> sys.stderr, "for help use --help"
            return None
