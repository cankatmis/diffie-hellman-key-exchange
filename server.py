import socket
from threading import Thread
from diffieHellman import DiffieHellman, decrypt


# The server class handles incoming client connections and secure communication using DH and AES
class Server:
    def __init__(self, host, port, p, g):
        self.host = host
        self.port = port
        self.p = p
        self.g = g

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print("Server listening on {}:{}".format(self.host, self.port))

        while True:
            client_socket, client_address = server_socket.accept()
            print("Connection from {}".format(client_address))
            thread = Thread(target=self.handle_client, args=(client_socket,))
            thread.start()

    def handle_client(self, client_socket):

        # Initialize a DiffieHellman instance with the provided p and g parameters
        dh = DiffieHellman(self.p, self.g)
        client_socket.sendall(str(dh.public_key).encode())

        client_public_key = int(client_socket.recv(1024).decode())
        shared_secret = dh.generate_shared_secret(client_public_key)

        while True:
            iv_length = int.from_bytes(client_socket.recv(4), byteorder='big')
            if not iv_length:
                break

            # Receive the IV and ciphertext from the client
            iv = client_socket.recv(iv_length)
            ciphertext_length = int.from_bytes(client_socket.recv(4), byteorder='big')
            ciphertext = client_socket.recv(ciphertext_length)

            # Display the received encrypted message
            encrypted_message = iv + ciphertext
            print(f"Received encrypted message: {encrypted_message.hex()}")

            # Decrypt the message using the shared AES key and the received IV
            plaintext = decrypt(iv, ciphertext, shared_secret)  # Decode the bytes to a string

            # Display the decrypted message
            print("Client: {}".format(plaintext))

        client_socket.close()
