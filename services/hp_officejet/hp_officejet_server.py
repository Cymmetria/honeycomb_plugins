# -*- coding: utf-8 -*-
"""HP OfficeJet Server Module."""
from __future__ import unicode_literals

from six.moves import socketserver
PJL_PORT = 9100
LOCALHOST_ADDRESS = "0.0.0.0"

INTERACTION_ALERT_NAME = "hp_officejet"
ATTACK_ALERT_NAME = "hp_path_traversal"
INFO_STATUS_RESPONSE = "@PJL INFO STATUS\r\nCODE=10003\r\nONLINE=TRUE\r\n\x0c"
INFO_ID_RESPONSE = "@PJL INFO ID\r\n\"HP OfficeJet Pro 8210\"\r\n\x0c"
FSQUERY_RESPONSE_TRAILER = " TYPE=FILE SIZE=4096\r\n\x0c"
SERVER_NAME = "OfficeJet Pro 8210"
ERROR = "error parsing stuff"


class PJLCommandHandler(socketserver.BaseRequestHandler):
    """PJL Command Requesrt Handler."""

    def alert(self, *args, **kwargs):
        """Raise alert."""
        self.alert_callback(*args, **kwargs)

    def handle(self):
        """Handle a PJL request."""
        # self.request is the client connection
        request = ""

        while True:
            char = self.request.recv(1).decode()

            if char == "":
                # Socket was closed.
                self.debug("Client closed the connection.")
                break

            request += char

            # Proper syntax for a PJL request requires it to end with a \n
            if char != "\n":
                continue

            # PJL commands must start with a @PJL
            if not request.startswith("@PJL "):
                request = ""
                continue

            self.debug("About to handle {request}".format(request=request))
            response = self.handle_command(request, self.client_address)
            self.debug("About to respond: {response}".format(response=response))

            if response != "":
                self.request.send(response)

            request = ""

        self.request.close()

    def handle_command(self, command, address):
        """Handle PJL Command."""
        response = ""
        argv = command.split(" ")[1:]

        self.debug("Args: {}".format(argv))
        if argv[0].strip() == "INFO":
            if argv[1].strip() == "STATUS":
                response = INFO_STATUS_RESPONSE
            if argv[1].strip() == "ID":
                response = INFO_ID_RESPONSE

        elif argv[0] == "FSDOWNLOAD":
            # argv[1] should be "FORMAT:BINARY"
            # argv[2] should be "SIZE=###", and can contain whitespaces (spaces
            # and tabs) around the "=".
            # argv[3] should be "NAME='PATHNAME'", and can also contain whitespaces.
            # In short, splitting to arguments here will give us an erratic result.
            # We rather strip away all the whitespaces and work with certainty.
            compacted_command = command.replace(" ", "").replace("\t", "")
            path_index = compacted_command.find('NAME="')
            if path_index == -1:
                response = ERROR
            else:
                # Does the command contain a path traversal?
                path = compacted_command[path_index:]
                if path.find("..") != -1:
                    self.alert(event_name=ATTACK_ALERT_NAME,
                               request=command,
                               orig_ip=address[0],
                               orig_port=address[1])
        elif argv[0] == "FSQUERY":
            # Pretend we queried the file successfully and it's 4096 bytes big
            # Generate the response by echoing the original query and adding some PJL-ordained crap
            response = command[:-1]  # minus <CR><LF>
            response += FSQUERY_RESPONSE_TRAILER
            self.alert(event_name=INTERACTION_ALERT_NAME,
                       request=command,
                       orig_ip=address[0],
                       orig_port=address[1])
        else:
            response = ERROR

        if response == ERROR:
            self.debug("Error handling command")
            response = ""

        return response


class PJLServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """PJL Server class."""

    def __init__(self, alert_callback, logger):
        self.info = logger.info
        self.debug = logger.debug

        alerting_client_handler = PJLCommandHandler
        alerting_client_handler.debug = logger.debug
        alerting_client_handler.info = logger.info
        alerting_client_handler.alert_callback = alert_callback
        socketserver.TCPServer.__init__(self, ((LOCALHOST_ADDRESS, PJL_PORT)), alerting_client_handler)

    def start(self):
        """Start PJL Server."""
        self.info("Starting PJL server on port {port}".format(port=PJL_PORT))
        try:
            self.serve_forever()
        except Exception as err:
            self.debug("Error: {error}".format(error=err))

    def stop(self):
        """Stop PJL Server."""
        self.server_close()
        self.info("PJL server stopped")

    def __str__(self):
        return SERVER_NAME
