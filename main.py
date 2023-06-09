#!/usr/bin/env python3

import argparse
import base64
from datetime import datetime
import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import logging
from pathlib import Path
import pickle
import socket
from threading import Thread
from urllib.parse import urlparse, parse_qs, unquote_plus


HTTPD_PORT = 3000
UDP_PORT = 5000
FILE_DATA = "./storage/data.json"


#{{{ UDP SERVER
def packet_encode(entity) -> bytes:
    return base64.b64encode(pickle.dumps(entity))

def packet_decode(entity: bytes):
    return pickle.loads(base64.b64decode(entity))

udpsock_server_keep_running = True

def udpsock_server(udpservsock: socket, fh) -> None:
    """ UDP server.
    Listen data stream, collect data to buf. Next Base64 encoded block
    is recognized by b'\t' delimiter at the end of block. Decoded Base64
    block is pickle serialized python object. Deserialized object have to be
    included as part of dictionary which is saved to already opened to write
    file fh. Flag udpsock_server_keep_running minimum each second is checked to
    determine if UDP server must be closed.
    """
    buf = b""
    udpservsock.settimeout(1)
    while udpsock_server_keep_running:
        try:
            data, addr = udpservsock.recvfrom(32000)
        except TimeoutError:
            continue
        logging.debug(f"Socket server: From {addr} Received message: {data}")
        buf += data
        while True:
            try:
                epsi = buf.index(b'\t') # end pack symbol index
            except ValueError:
                break
            entity = packet_decode(buf[0:epsi])
            buf = buf[epsi+1:]
            print(json.dumps({datetime.now().strftime("%Y-%m-%d %H-%M-%S.%f"): entity},
                        indent=2, ensure_ascii=False), file=fh)
            fh.flush()
#}}}


class Ht11(BaseHTTPRequestHandler):
    # Parameters how to manage persistent HTTP/1.1 open connection
    KEEPALIVE = "timeout=5, max=30"
    # Content-Type MIME headers by extensions
    CONT_TYPES = { '.css': 'text/css'
                 , '.html': 'text/html'
                 , '.png': 'image/x-png'
                 , '.ico': 'image/x-icon'
                 }
    # Web server root dir is the dir of the progran file
    path_root_dir = Path(__file__).parent
    # Next free session id
    sid_last = 1
    # Current known session register. Format:
    # sid_reg[(sid] =
    #     [ (ip, port), username, [(from_iport, username, msg), ...] ]
    sid_reg = {}
    # Current not sent message list. Format:
    # [ (from_ipport, username, addresee, msg), ...]
    msg_list = []

    def clipport(self, *args) -> str:
        if len(args) == 0:
            return f"{self.client_address[0]}:{self.client_address[1]}"
        if len(args) == 1:
            return f"{args[0][0]}:{args[0][1]}"
        else:
            return f"{args[0]}:{args[1]}"

    @staticmethod
    def find_resource(path):
        """Determine file to be sent as response"""
        path = path[1:]
        pathfile = Ht11.path_root_dir / (path + ".gz")
        if Path.exists(pathfile):
            return 200, str(pathfile), pathfile.stat().st_size
        pathfile = Ht11.path_root_dir / path
        if Path.exists(pathfile):
            return 200, str(pathfile), pathfile.stat().st_size
        pathfile = Ht11.path_root_dir / "error.html.gz"
        return 404, str(pathfile), pathfile.stat().st_size

    def do_GET(self):
        parsed = urlparse(self.path)

        # Get the request path, this new path does not have the query string
        path = parsed.path

        if path == '/':
            path = "/index.html"

        response_code, fullfilename, content_length = Ht11.find_resource(path)
        self.send_response(response_code)

        if fullfilename.lower().endswith('.gz'):
            logging.debug("Content-Encoding: gzip")
            self.send_header("Content-Encoding", "gzip")

        try:
            ext = path[path.rindex('.'):]
            logging.debug(f"Extension {ext}, Content-Type: {Ht11.CONT_TYPES[ext]}")
            self.send_header("Content-Type", Ht11.CONT_TYPES[ext])
        except (ValueError, KeyError):
            logging.debug(f"Absent Content-Type for resource '{path}'")

        if Ht11.KEEPALIVE:
            self.send_header("Connection", "keep-alive")
            self.send_header("keep-alive", Ht11.KEEPALIVE)
        self.send_header("Content-Length", str(content_length))
        self.end_headers()

        try:
            with open(fullfilename, "rb") as fh:
                self.wfile.write(fh.read())
        except (FileNotFoundError, BrokenPipeError) as e:
            logging.debug(f"Handling problem with resourse {path} = "
                          f"file {fullfilename}: " + str(e))

    def message_engine(self, value_map):
        """
        Message handler
        """
        ## session_id | username | To do
        ##---------------------------------------------------------------------
        ##     0      | ''       | create sid_req element with sid_last++
        ##     0      | username | create sid_req element with sid_last++
        ##     >0     | ''       | find username by sid_reg
        ##     >0     | username | normalize_reg(), save username in sid_reg

        sid = int(value_map.get("session_id", ["0"])[0])
        username = value_map.get("username", [""])[0]
        addressee = value_map.get("addressee", [""])[0]
        message = value_map.get("message", [""])[0]

        if sid == 0:
            for sessid in Ht11.sid_reg.keys():
                if username.lower() == Ht11.sid_reg[sessid][1].lower():
                    # There is old connection with the same username: use it
                    logging.debug(f"{self.clipport()}#{sid}: assign already existent "
                                  f"session id {Ht11.sid_reg[sessid][0]} for username "
                                  f"'{username}'")
                    sid = Ht11.sid_reg[sessid][0]
                    Ht11.sid_reg[sessid][0] = self.clipport()
                    break
            else: # no break
                Ht11.sid_reg[Ht11.sid_last] = [ self.clipport(), username, [] ]
                logging.debug(f"{self.clipport()}#{sid}: assign new session id "
                              f"{Ht11.sid_last} for username '{username}'")
                sid = Ht11.sid_last
                Ht11.sid_last += 1
        else:
            if sid in Ht11.sid_reg.keys():
                Ht11.sid_reg[sid][0] = self.clipport()
                if username.lower() != Ht11.sid_reg[sid][1].lower():
                    logging.debug(f"{self.clipport()}#{sid}: client changed your "
                                  f"username '{Ht11.sid_reg[sid][1]}' with "
                                  f"'{username}'")
                Ht11.sid_reg[sid][1] = username
            else:
                logging.debug(f"{self.clipport()}#{sid}: server was restarted "
                              f"but old client still tries to connect")
                Ht11.sid_reg[sid] = [ sid, username, [] ]
                if Ht11.sid_last <= sid:
                    Ht11.sid_last = sid + 1

        # Save message in list
        if message != "" and username != "" and addressee != "":
            Ht11.msg_list.append((self.clipport(), username, addressee, message))

        # Distribute messages between connections
        for i in range(len(Ht11.msg_list)):
            ipport, name, addrs, msg = Ht11.msg_list[i]
            for sessid in Ht11.sid_reg.keys():
                if addrs.lower() == Ht11.sid_reg[sessid][1].lower():
                    Ht11.sid_reg[sessid][2].append((ipport, name + "->" + addrs, msg))
                    Ht11.msg_list[i] = None
        Ht11.msg_list = [ it for it in Ht11.msg_list if it is not None ]

        # Prepare message for current client
        response = ({
            "session_id": sid,
            "message_list": Ht11.sid_reg[sid][2]
        })
        Ht11.sid_reg[sid][2] = []

        #{{{ UDP SERVER AS LOGGER
        if message != "":
            # b'\t" is the data block delimiter
            Ht11.udpsock.sendto(packet_encode({
                    "address": self.clipport(),
                    "username": username,
                    "addressee": addressee,
                    "message": message
                }) + b'\t', ("127.0.0.1", UDP_PORT))
        #}}}

        return json.dumps(response)

    def do_POST(self):
        """
        @Requests:
        /exit
            has no parameters
        /send_message
            session_id
            username
            addressee
            message
        /polling_message
            session_id
            username
        @Response
        /exit
            { message: "Bye" }
        /send_message
            { session_id: sid
              message: [ [ "ip:port", username, message ], ... ] }
        /polling_message
            the same as /send_message
        @Error request
            { alert: message }
        """
        content_length = int(self.headers.get("Content-Length"))
        reqbody = self.rfile.read(content_length)
        parsed = urlparse(self.path)
        path = parsed.path

        reqbody = unquote_plus(reqbody.decode("utf-8"))
        value_map = parse_qs(reqbody)

        logging.debug(f"Request path '{path}': body '{reqbody}' = '{value_map}'")

        if "/polling_message" == path:
            response = self.message_engine(value_map)
        elif "/send_message" == path:
            response = self.message_engine(value_map)
        else:
            response = json.dumps({ "alert": f"Wrong request path '{path}'" })

        logging.debug(f"Response = {response}")

        response = bytes(response, "utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if Ht11.KEEPALIVE:
            self.send_header("Connection", "keep-alive")
            self.send_header("keep-alive", Ht11.KEEPALIVE)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()

        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug("---[ CLIENT REGISTRY ]---")
            for sid, pars in Ht11.sid_reg.items():
                logging.debug(f">>> #{sid}: {pars}")
            logging.debug("---[ MESSAGE LIST ]---")
            for ipport, name, addrs, msg in Ht11.msg_list:
                logging.debug(f">>> {ipport} {name}->{addrs}: '{msg}'")

        try:
            self.wfile.write(response)
        except (FileNotFoundError, BrokenPipeError) as e:
            logging.debug(f"Handling problem for response path {path}: "
                           + str(e))

    # def log_message(self, format: str, *args: Any) -> None:
    #     """Do not print log"""
    #     return


def httpd_server(web_port, udp_port):
    """
    Run HTTP server and UDP server. UDP socket and file
    to save history is open here and sending as args here
    to avoid synchronization issues at start.
    """
    global udpsock_server_keep_running

    Ht11.protocol_version = "HTTP/1.1"
    Ht11.udpsock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    try:
        udpservsock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        udpservsock.bind(("127.0.0.1", udp_port))
    except Exception as e:
        logging.error("Udp server socket error: " + str(e))
        exit(1)

    try:
        fh = open(FILE_DATA, "w")
    except Exception as e:
        logging.error("JSON file create error: " + str(e))
        exit(1)

    try:
        httpd = ThreadingHTTPServer(('0.0.0.0', web_port), Ht11)

        th = Thread(target=udpsock_server, args=(udpservsock, fh))
        th.start()

        httpd.serve_forever()

    except (OSError, PermissionError, OverflowError, KeyboardInterrupt):
        udpsock_server_keep_running = False
        httpd.server_close() # do not forget call it
        return

def main():
    """
    Default ports can be changed with help of command line arguments.
    HTTP server is listened request in all available interfaces.
    """
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('port', metavar='T', type=int, nargs='?',
                    help='HTTP web-server port')
    parser.add_argument('-u', '--uport', metavar='U', type=int, nargs='?',
                    help='UDP port for communication between web-servers')
    args = parser.parse_args()
    if args.port is None:
        args.port = HTTPD_PORT
    if args.uport is None:
        args.uport = UDP_PORT

    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    logging.info(f"WEBSERVER PORT: {args.port}")
    logging.info(f"UDP COMM PORT: {args.uport}")

    httpd_server(args.port, args.uport)

if __name__ == "__main__":
    main()

