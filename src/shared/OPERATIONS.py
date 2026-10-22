import getpass
import inspect
import os

import PROTOCOLS
import encryptions
from loguru import logger
import OPERATIONS

def recv_encyrpted_msg_by_client(client_socket, str_aes_key):
    data = PROTOCOLS.recv_protocoled_msg(client_socket)
    iv = data[:16]
    enceypted_msg = data[16:]
    data_decrypted = encryptions.aes_decryption(enceypted_msg, str_aes_key, iv)
    msg_unpaded_decrpyed = encryptions.aes_unpadder(data_decrypted)
    if msg_unpaded_decrpyed.startswith(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'):
        data = msg_unpaded_decrpyed
    else:
        data = msg_unpaded_decrpyed.decode('utf-8')
   # logger.info(f"the decrypted data is {data}")
    return data


def encrypt_msg_by_aes(msg,aes_key):
    caller_frame = inspect.stack()[1]
    caller_filename = os.path.basename(caller_frame.filename)
    iv = encryptions.iv_creator()
    logger.info(f"{caller_filename} || the iv that the customer has randomised is {iv}")
    if isinstance(msg,str):
        massage_ived = msg.encode("utf-8")
    else:
        massage_ived = msg

    padded_msg = encryptions.aes_padder(massage_ived)
    msg_encrypted = encryptions.aes_encryption(padded_msg, aes_key, iv)
    final_msg = iv + msg_encrypted
    if len(padded_msg) < 50:
        logger.info(f" {caller_filename} || the padded msg is {padded_msg}")
        logger.info(f"{caller_filename} || the encrypted msg is {msg_encrypted}")
        logger.info(f"{caller_filename} ||: the final msg is {final_msg}")
    return final_msg

def send_encyrpted_msg(msg, str_aes_key, client_socket):
    final_msg = OPERATIONS.encrypt_msg_by_aes(msg, str_aes_key)
    client_socket.send(PROTOCOLS.create_protocoled_msg(final_msg))


def whoami():
    return getpass.getuser()

