import base64
import os
from loguru import logger
from sympy import randprime
import secrets
import PROTOCOLS
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives import padding

#--------------------------------------------------------------

def create_pq():
    q = randprime(pow(10,55), pow(10,85))
    p = randprime(pow(10,55), pow(10,85))
    while q == p:
        p = randprime(1, 100)
    logger.info(f"Successfully created p,q for RSA key exchange ")
    return p,q

def create_N_TOTIENT_N(p,q):
    N = p*q
    Totient = (p-1)*(q-1)
    logger.info(f"Successfully created N,totient for RSA key exchange")

    return N , Totient

def create_public_key(totient):
    p= randprime(1,totient)
    while not if_gcd(p,totient):
        p= randprime(1,totient)
    logger.info(f"Successfully created public key")
    return p



def generate_private_key(e, totient):
    """
    Calculates the private key 'd' using the Extended Euclidean Algorithm.
    Satisfies the condition: (e * d) % totient == 1
    """
    a = totient
    b = e
    x1 = 0
    x2 = 1

    while b != 0:

        q = a // b
        r = a % b

        x_new = x1 - q * x2

        # Shift states forward
        a = b
        b = r
        x1 = x2
        x2 = x_new

    # If the resulting coefficient is negative, convert it to a positive equivalent
    if x1 < 0:
        x1 += totient
    logger.info(f"Successfully created private key")
    return x1

def encrypt_with_public_key(e,N, msg):
    return pow(msg, e, N)

def decrypt_with_private_key(N, cypher, d):
    return pow(cypher,d,N)



def if_gcd(number, totient):
    A = max(number, totient)
    B = min(number, totient)
    if A==1 or B==1:
        return True

    while B != 0:
        r=A%B
        if r==1:
            return True
        A=B
        B=r
    return False

def create_aes_key():
    logger.debug("AES key established")
    return secrets.token_bytes(32)

def send_public_params_to_client(client_socket, public_key, N):
    """Send the server's public key and modulus (N) to the client."""
    client_socket.send(PROTOCOLS.create_protocoled_msg(str(public_key)))
    client_socket.send(PROTOCOLS.create_protocoled_msg(str(N)))

#function that exchange the symetric key with the client
def server_key_exchange(client_socket, public_key, private_key, N):
    #sent public params to client
    send_public_params_to_client(client_socket, public_key, N)
    #recieve the private aes key so we can talk securely with client
    encrypted_aes_key = PROTOCOLS.recv_protocoled_msg(client_socket)
    if not encrypted_aes_key:
        logger.error("key exchange failed - client disconnected")
        return None
    aes_key_int = int.from_bytes(encrypted_aes_key, byteorder='little')
    decrypted_aes_key = decrypt_with_private_key(N,aes_key_int,private_key)
    return decrypted_aes_key

#-------------------------------------------------------------#
#AES encryption & decryption Area:


def aes_key_creation():
    key = os.urandom(16)
    return key

def aes_encryption(msg, key , iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_msg = (encryptor.update(msg) + encryptor.finalize())
    return cipher_msg

def iv_creator()->bytes:
    """
    :return:(bytes) - a random 16 bytes number - used for iv (for aes encryption)
    """
    return os.urandom(16)

def aes_decryption(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def aes_padder(msg):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(msg)
    padded_data += padder.finalize()
    return padded_data

def aes_unpadder(msg_decrypted):
    unpadder = padding.PKCS7(128).unpadder()
    unpaded_data = unpadder.update(msg_decrypted)
    unpaded_data += unpadder.finalize()
    return unpaded_data

def base_64_encoder(msg: bytes) -> str:
    return base64.b64encode(msg).decode('utf-8')

def base_64_decoder(msg:str)->bytes:
    return base64.b64decode(msg.encode('utf-8'))