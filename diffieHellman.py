import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# The DiffieHellman class implements the Diffie-Hellman key exchange algorithm
class DiffieHellman:
    def __init__(self, p, g):
        # Initialize the prime number (p) and the generator (g) parameters
        self.p = p
        self.g = g

        # Generate a private key as a random number between 2 and p - 2
        self.private_key = random.randint(2, p - 2)

        # Calculate the public key using g ^ private_key mod p
        self.public_key = pow(g, self.private_key, p)

    # Generate the shared secret using the other party's public key and the private key
    # shared_secret = other_public_key ^ private_key mod p
    def generate_shared_secret(self, other_public_key):
        return pow(other_public_key, self.private_key, self.p)


# Hash the shared secret using SHA-256 to derive a 256-bit key for AES encryption
def sha256(key):
    return hashlib.sha256(str(key).encode()).digest()


# Encrypt a message using AES-256 in CBC mode with a randomly generated IV
def encrypt(plaintext, key):
    cipher = AES.new(sha256(key), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv, ciphertext


# Decrypt a message using AES-256 in CBC mode with the provided IV
def decrypt(iv, ciphertext, key):
    cipher = AES.new(sha256(key), AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')
