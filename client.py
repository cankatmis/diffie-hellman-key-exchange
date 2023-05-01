import argparse
import socket
from diffieHellman import DiffieHellman, encrypt
from server import Server


# The client class connects to the server and handles secure communication using DH and AES
class Client:
    def __init__(self, host, port, p, g):
        self.host = host
        self.port = port
        self.p = p
        self.g = g

    def start(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))
        print("Connected to {}:{}".format(self.host, self.port))

        # Initialize a DiffieHellman instance with the provided p and g parameters
        dh = DiffieHellman(self.p, self.g)
        server_public_key = int(client_socket.recv(1024).decode())
        client_socket.sendall(str(dh.public_key).encode())

        shared_secret = dh.generate_shared_secret(server_public_key)

        while True:

            # Read the message from the user
            message = input("Enter your message (type 'exit' to quit): ")
            if message.lower() == 'exit':
                break

            # Encrypt the message using the shared AES key
            iv, ciphertext = encrypt(message, shared_secret)

            # Display the encrypted message
            print(f"Encrypted message: {iv.hex()}{ciphertext.hex()}")

            # Send the IV and ciphertext to the server
            client_socket.sendall(len(iv).to_bytes(4, byteorder='big'))
            client_socket.sendall(iv)
            client_socket.sendall(len(ciphertext).to_bytes(4, byteorder='big'))
            client_socket.sendall(ciphertext)

        client_socket.sendall(len(b'').to_bytes(4, byteorder='big'))
        client_socket.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Diffie-Hellman and AES encrypted communication")
    parser.add_argument("mode", choices=["server", "client"], help="Run in server or client mode")
    parser.add_argument("--host", default="localhost", help="Host address (default: localhost)")
    parser.add_argument("--port", type=int, default=5000, help="Port number (default: 5000)")
    parser.add_argument("--prime", type=int, default=23, help="Diffie-Hellman prime (default: 23)")
    parser.add_argument("--generator", type=int, default=5, help="Diffie-Hellman generator (default: 5)")

    args = parser.parse_args()

    if args.mode == "server":

        # Start the server with the provided host, port, prime, and generator parameters
        server = Server(args.host, args.port, args.prime, args.generator)
        server.start()
    elif args.mode == "client":

        # Start the client with the provided host, port, prime, and generator parameters
        client = Client(args.host, args.port, args.prime, args.generator)
        client.start()
