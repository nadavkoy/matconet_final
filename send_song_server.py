import threading
import socket
from AES import *
from KeyGenerator import *
import wx


SONG = "F:\silent_disco\laughing and not being normal.mp3"


class Server(object):
    def __init__(self):
        self.server_socket = socket.socket()
        self.server_socket.bind(('0.0.0.0', 4500))
        self.server_socket.listen(10)

        # for encryption:
        self.rsa = Cryptonew()  # creating a new Cryptonew object to encrypt and decrypt with RSA
        self.public_key = self.rsa.get_public()  # getting the public RSA key
        self.private_key = self.rsa.get_private()  # getting the private RSA key

    def accept(self):
        return self.server_socket.accept()


class ClientHandler(threading.Thread):
    def __init__(self, address, socket, public_key, private_key, rsa):
        super(ClientHandler, self).__init__()
        self.sock = socket
        self.address = address

        # for encryption:
        self.rsa = rsa  # rsa is a Cryptonew object that we got from server as a parameter
        self.key = ''  # this variable will hold the AES that we'll get from the client
        self.public = public_key  # the public key we got from the server as a parameter
        self.private = private_key  # the private key we got from the server as a parameter
        self.aes = AESCrypt()  # creating a AESCrypt object to encrypt and decrypt with AES.

    def get_client_key(self):
        """ decoding the encryption key """
        self.sock.send(self.rsa.pack(self.public))  # sending the pickled public key to the client
        encrypted_key = self.sock.recv(1024)  # getting the AES key encrypted with the public key
        self.key = self.rsa.decode(encrypted_key, self.private)  # decoding the encrypted key with the private key
        self.sock.send('got the key!')  # sends a message to the client to approve that received

    def decrypt_message(self, encrypted_client_request):
        """ decrypts the client's request """
        return self.aes.decryptAES(self.key, encrypted_client_request).split('0')[0]  # decrypt the message with AES key

    def encrypt_message(self, response):
        """ encrypts the server's response """
        return self.aes.encryptAES(self.key, response).ljust(1024, '0')  # encrypt the message with AES key

    def divide_song(self, song_file):
        #  taking forever to send a song. must change!!
        file = open(song_file, 'rb')  # opening file
        file_content = file.read()  # reading file's content

        file_size = len(file_content)

        packet_size = 1024
        packets_list = []
        packets_num = file_size / packet_size  # calculating the amount of packets needed to send the entire song.
        last_packet_size = file_size % packet_size

        for packet in range(packets_num):
            packets_list.append(file_content[:packet_size])
            file_content = file_content[packet_size:]

        if last_packet_size != 0:
            packets_list.append(file_content)

        return packets_list

    def send_song(self, packets_list):
        self.sock.send(str(len(packets_list)))
        self.sock.recv(1024)

        for packet in packets_list:
            self.sock.send(packet)
            self.sock.recv(1024)

    def run(self):
        self.get_client_key()
        #packets_list = self.divide_song(SONG)
        #self.send_song(packets_list)

        while True:
            client_request = self.sock.recv(1024)
            client_decrypted_request = self.decrypt_message(client_request)
            response = 'hello, ' + client_decrypted_request
            self.sock.send(self.encrypt_message(response))
            print response


def main():
    server = Server()
    while True:
        socket, address = server.accept()
        client_hand = ClientHandler(address, socket, server.public_key, server.private_key, server.rsa)
        client_hand.start()


if __name__ == '__main__':
    main()

