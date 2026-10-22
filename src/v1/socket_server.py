import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))

SCREENSHOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "_local", "screenshot")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)
SCREENSHOT_PATH = os.path.join(SCREENSHOT_DIR, "v1_myscreenshot.png")
# ---- end path bootstrap ----
import argparse
import socket
import threading
from loguru import logger
import OPERATIONS
import PROTOCOLS
import os
import getpass
import pyautogui
import encryptions
#-----------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Socket server (educational, lab use only)")
    parser.add_argument("--port", type = int ,required=True, help="Port number for server")
    parser.add_argument("--host-ip", required=True, help="Host IP")
    return parser.parse_args()
#-----------------------------------------------------------------------
users = {}
#basic function that handle the client input ot the server
COMMANDS = {'cat','dir','whoami','SCREENSHOT','SEND_IMG'}
#set encryption numbers:
p,q = encryptions.create_pq()
N, totienty = encryptions.create_N_TOTIENT_N(p,q)
public_key = encryptions.create_public_key(totienty)
privateKey = encryptions.generate_private_key(public_key,totienty)
#-----------------------------------------------------------------------

def setup_client(client_socket):
    """Register the client and perform key exchange. Returns (name, aes_key) or None."""
    name = PROTOCOLS.recv_protocoled_msg(client_socket)
    if not (client_socket and public_key and privateKey and N):
        logger.error("key material missing")
        return None
    aes_key = encryptions.server_key_exchange(client_socket, public_key, privateKey, N)
    byte_length = (aes_key.bit_length() + 7) // 8
    str_aes_key = (aes_key.to_bytes(byte_length, byteorder='little'))
    return name, str_aes_key

def cmd_cat(aes_key, conn,args):
    logger.info("client has asked for 'cat' command")
    cwd = os.getcwd()
    final_url = os.path.abspath(f"{cwd}/{os.path.basename(args[0])}")
    logger.info(f"the last url is {final_url} that the customer asked is: ")
    try:
        with open(final_url, "r") as f:
            content = f.read()
            OPERATIONS.send_encyrpted_msg(content, aes_key, conn)
    except FileNotFoundError:
        logger.error("file not found")
        OPERATIONS.send_encyrpted_msg("file not found", aes_key, conn)


def cmd_dir(aes_key, conn,args):
    logger.info("client has asked for 'dir' command")
    cwd = os.getcwd()
    files = os.listdir(cwd)
    str_listed = ",".join(files)
    OPERATIONS.send_encyrpted_msg(str_listed, aes_key, conn)

def cmd_whoami(aes_key, conn,args):
    logger.info("client has asked for 'whoami' command")
    user = OPERATIONS.whoami()
    OPERATIONS.send_encyrpted_msg(user, aes_key, conn)
    logger.info(f"the user {user} has asked for the server's identity")

def cmd_screenshot(aes_key, conn,args):
    pyautogui.screenshot(SCREENSHOT_PATH)
    OPERATIONS.send_encyrpted_msg("screenshot successfuly", aes_key, conn)


def cmd_send_img(aes_key, conn,args):
    try:
        URL_PIC = SCREENSHOT_PATH
        with open(URL_PIC, 'rb') as f:
            img_data = f.read()
            logger.info("the img_data has loaded successfuly")
            OPERATIONS.send_encyrpted_msg(img_data, aes_key, conn)
    except FileNotFoundError:
        logger.error("file not found")
        OPERATIONS.send_encyrpted_msg("no image. please use SCREENSHOT before", aes_key, conn)

COMMAND_HANDLERS = {
    "cat":        cmd_cat ,
    "dir":        cmd_dir ,
    "whoami":     cmd_whoami,
    "SCREENSHOT": cmd_screenshot,
    "SEND_IMG": cmd_send_img
}

def handle_client(client_socket, client_address):
    name, aes_key = setup_client(client_socket)
    users[client_address] = name.decode('utf-8')
    logger.debug(f"the client name is : {name.decode('utf-8')}")
    logger.info(f"Agents in system: {users}")
    try:
        while True:
            data = OPERATIONS.recv_encyrpted_msg_by_client(client_socket, aes_key)
            if not data or data == "bye":
                break
            command, *args = data.split()
            handler = COMMAND_HANDLERS.get(command)
            if handler:
                try:
                    handler(aes_key, client_socket, args)
                except Exception as e:
                    logger.error(f"handler for '{command}' failed: {e}")
                    OPERATIONS.send_encyrpted_msg("command failed", aes_key, client_socket)
            else:
                OPERATIONS.send_encyrpted_msg("no command found", aes_key, client_socket)
    finally:
        #logger.info(f"{users[client_address]}: {data}")
        del users[client_address]
        logger.info(f"user {client_address} disconnected and removed")
        client_socket.close()
        logger.info(f"Agents in system: {users}")

#the heart of the server - which can run multiple clients - via multithreading
def main():
    args = parse_args()
    HOST = args.host_ip  # ip that the server will listen on
    PORT = args.port  # Port to listen on

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_scoket:
        server_scoket.bind((HOST, PORT))
        server_scoket.listen()
        server_scoket.settimeout(1.0)
        logger.info("Listening for connections on port {}".format(PORT))

        while True:
            try:
                client_socket, client_address = server_scoket.accept()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                logger.info("Stopping server...")
                break
            logger.info(f"Connected by {client_address}")
            t1 = threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True)
            t1.start()
if __name__ == '__main__':
    main()