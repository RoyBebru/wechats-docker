#!/usr/bin/env python3

import argparse
import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import logging
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote_plus

HTTPD_PORT = 3000

class Ht11(BaseHTTPRequestHandler):
#   KEEPALIVE = "timeout=5, max=30"
    KEEPALIVE = ""
    CONT_TYPES = { '.css': 'text/css'
                 , '.html': 'text/html'
                 , '.png': 'image/x-png'
                 , '.ico': 'image/x-icon'
                 }
    keep_running = True
    path_root_dir = Path(__file__).parent
    sid_last = 1
    # Format:
    # sid_reg[(sid] =
    #     [ (ip, port), username, [(from_iport, username, msg), ...] ]
    sid_reg = {}
    # Format:
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

        # print(f"Socket: {self.server.socket}; id={id(self.server.socket)}")

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
        response = Ht11.dict_to_json_str({
            "session_id": sid,
            "message_list": Ht11.sid_reg[sid][2]
        })
        Ht11.sid_reg[sid][2] = []
        return response

    @staticmethod
    def dict_to_json_str(dc: dict) -> str:
        return json.dumps(dc)

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

        if "/exit" == path:
            logging.debug("Bye!")
            Ht11.keep_running = False
            response = json.dumps({ "message": "Bye" })
        elif "/polling_message" == path:
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

#    def log_message(self, format: str, *args: Any) -> None:
#       """Do not print log"""
#       return


def httpd_server(web_port):
    Ht11.keep_running = True
    Ht11.protocol_version = "HTTP/1.1"

    try:
        httpd = ThreadingHTTPServer(('0.0.0.0', web_port), Ht11)

        # httpd.serve_forever()

        while Ht11.keep_running:
            httpd.handle_request()
            # to do something useful after request

    except (OSError, PermissionError, OverflowError, KeyboardInterrupt):
        pass

    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('port', metavar='T', type=int, nargs='?',
                    help='HTTP web-server port')
    args = parser.parse_args()
    if args.port is None:
        args.port = HTTPD_PORT

    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    logging.info(f"WEBSERVER PORT: {args.port}")

    httpd_server(args.port)
