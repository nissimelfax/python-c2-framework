import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))
# ---- end path bootstrap ----
IMG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "_local", "screenshot")
os.makedirs(IMG_DIR, exist_ok=True)
OUTPUT_IMG_PATH = os.path.join(IMG_DIR, "v1_output_image.png")
import socket
import OPERATIONS
import PROTOCOLS
import encryptions
from loguru import logger
import argparse
logger.remove()

logger.add(
    sys.stderr,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{function}</cyan> | <level>{message}</level>",
    level="INFO"
)
logger.add("my_app.log", rotation="5 MB", level="DEBUG")
logger.debug("the client has run")

def parse_args():
    p = argparse.ArgumentParser(description="Socket agent (educational, lab use only)")
    p.add_argument("--host", default="127.0.0.1", help="Server IP")
    p.add_argument("--port", type=int, required=True, help="Server port")
    return p.parse_args()

def main():
    args = parse_args()
    HOST = args.host
    PORT = args.port
    SOCKET_TIMEOUT = 5
# Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # Connect to the remote server
        client_socket.connect((HOST, PORT))
        client_socket.settimeout(SOCKET_TIMEOUT)
        name = input("Enter your name: ")
        #send the name according to the network protocol
        client_socket.send(PROTOCOLS.create_protocoled_msg(name))
        logger.info("the name has been sent successfully")

        #recieve the the public key and N
        servers_public_key = PROTOCOLS.recv_protocoled_msg(client_socket).decode()
        servers_n = PROTOCOLS.recv_protocoled_msg(client_socket).decode()

        #encrypt the aes with the server's public key, and sent it to the server - encrypted
        aes_key = encryptions.aes_key_creation()
        int_aes_key = int.from_bytes(aes_key, byteorder='little')
        encrypted_aes_key = encryptions.encrypt_with_public_key(int(servers_public_key), int(servers_n), int_aes_key)
        byte_length = (encrypted_aes_key.bit_length() + 7) // 8
        aes_key_in_bytes = encrypted_aes_key.to_bytes(byte_length, byteorder='little')
        client_socket.send(PROTOCOLS.create_protocoled_msg(aes_key_in_bytes))

        while True:
            msg  = input("Enter your massage: ")
            OPERATIONS.send_encyrpted_msg(msg, aes_key, client_socket)
            if msg == "bye":
                break
            try:
                #recv the first part of protocol - the length of the next data + type of msg
                decrypted_msg_back = OPERATIONS.recv_encyrpted_msg_by_client(client_socket,aes_key)
                if len(decrypted_msg_back) < 50:
                    logger.debug(f"the last full msg is : {decrypted_msg_back}")
                if decrypted_msg_back and msg != "SEND_IMG":
                    print(decrypted_msg_back)
                if msg == "SEND_IMG":
                    URL_PIC = OUTPUT_IMG_PATH
                    with open(URL_PIC, "wb") as f:
                        f.write(decrypted_msg_back)
                        logger.debug("the img has been received successfully")
            except socket.timeout:
                logger.debug("Timeout occurred")
            except ConnectionResetError:
                logger.debug("Client closed connection")

        client_socket.close()


if __name__ == "__main__":
    main()