from loguru import logger


LEN_OF_HEADER_PROTOCOL = 6
def length_calculate(txt:str) -> int:
    """
    calculate the length of the msg by the client
    :param txt(str) :the msg which will send to next side:
    :return:len(txt)(int) : the length of the msg
    """
    return len(txt)


def create_protocoled_msg(txt):
    if isinstance(txt, str):
        bytes_length = length_calculate(txt).to_bytes(LEN_OF_HEADER_PROTOCOL, byteorder='little')
        #next line wont work beacuse its bytes - cant print with str
        #print(f"bytes length of msg : {bytes_length}")
        full_msg = bytes_length + txt.encode('utf-8')
        #print(f"the msg that the client want to send is : {full_msg}")
        return full_msg
    elif isinstance(txt, bytes):
        logger.info("the type of input is bytes, may be img")

        bytes_length = (length_calculate(txt)).to_bytes(LEN_OF_HEADER_PROTOCOL, byteorder='little')
        full_msg = bytes_length + txt
        return full_msg


def recv_exact(client_socket, int_len):
    x=b''
    total_msg=[]
    integer_length = int(int_len)
    while integer_length >0:
        try:
            x= client_socket.recv(integer_length)
            if x:
                integer_length = integer_length - len(x)
                total_msg.append(x)
            else:
                logger.error("client closed connection")
                logger.error("Client closed connection")
                break
        except ConnectionResetError:
             logger.error("Client closed connection")
             break
        except ConnectionAbortedError:
               logger.error("Aborted connection")
               break
        except client_socket.timeout:
            logger.error("Client closed connection")
            break
    logger.info("the client has recieved the server's messsage ")
    #print(f"Received {b''.join(total_msg)}")
    return b''.join(total_msg)


def recv_protocoled_msg(client_socket) -> bytes:
    """Receive one framed message: read the fixed header, decode the length, read exactly that many bytes."""
    header = recv_exact(client_socket, LEN_OF_HEADER_PROTOCOL)
    if not header:
        return b''                         # הצד השני סגר
    length = int.from_bytes(header, byteorder='little')
    return recv_exact(client_socket, length)

