# -*- coding: utf-8 -*-
"""PJL Server Module."""
from __future__ import unicode_literals

import socket  # For socket.timeout exception
import threading

from six.moves import socketserver

from common_strings import STARTUP_MSG, SHUTDOWN_MSG, ERROR_MSG

LOCALHOST_ADDRESS = "0.0.0.0"
PJL_PORT = 9100

INTERACTION_ALERT_NAME = "xerox_pjl_interaction"
PATH_TRAVERSAL_ALERT_NAME = "xerox_path_traversal"
INFO_STATUS_RESPONSE = """@PJL INFO STATUS\r\nCODE=35078\r\nDISPLAY=""\r\nONLINE=TRUE\r\n\x0c"""
INFO_ID_RESPONSE = """@PJL INFO ID\r\n"Xerox WorkCentre 6605DN"\r\n\x0c"""
FSQUERY_RESPONSE_TRAILER = " TYPE=FILE SIZE=4096\r\n\x0c"
SERVER_NAME = "Xerox WorkCentre 6605DN PJL Server"
ERROR = "error parsing stuff"
XEROX_6605DN_CLIENT_TIMEOUT = 120
ALERTS = [INTERACTION_ALERT_NAME, PATH_TRAVERSAL_ALERT_NAME]


class ThreadingPJLServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threading SocketServer stub class."""


class PJLCommandHandler(socketserver.BaseRequestHandler):
    """PJL Command Request Handler."""

    def alert(self, *args, **kwargs):
        """Raise alert."""
        self.alert_callback(*args, **kwargs)

    def handle(self):
        """Handle a request."""
        # self.request is the client connection
        self.request.settimeout(XEROX_6605DN_CLIENT_TIMEOUT)
        pjl_request = ""

        while True:
            try:
                char = self.request.recv(1).decode()
            except socket.timeout:
                # Close the client connection abruptly to imitate the actual 6605dn printer
                self.request.shutdown(0)
                break

            if char == "":
                # Socket was closed.
                self.debug("Client closed the connection.")
                break

            pjl_request += char

            # Proper syntax for a PJL request requires it to end with a \n
            if char != "\n":
                continue

            # PJL commands must start with a @PJL
            if not pjl_request.startswith("@PJL "):
                pjl_request = ""
                continue

            self.debug("About to handle {request}".format(request=pjl_request))
            response = self.handle_command(pjl_request, self.client_address)
            self.debug("About to respond: {response}".format(response=response))

            if response != "":
                self.request.send(response.encode())

            pjl_request = ""

        self.request.close()

    def handle_command(self, command, address):
        """Handle a specific command."""
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
            # In short, splitting to arguments here will give me an erratic result.
            # We rather strip away all the whitespaces and work with certainty.
            compacted_command = command.replace(" ", "").replace("\t", "")
            path_index = compacted_command.find('NAME="')
            if path_index == -1:
                response = ERROR
            else:
                # Path traversal?
                path = compacted_command[path_index:]
                if path.find("..") != -1:
                    self.alert(event_name=PATH_TRAVERSAL_ALERT_NAME,
                               request=command,
                               orig_ip=address[0],
                               orig_port=address[1])
        elif argv[0] == "FSQUERY":
            # Pretend we queried the file successfully and it's 4096 bytes big
            # Generate the response by echoing the original query and adding some PJL-ordained crap
            response = command[:-1]  # minus <LF>
            response += FSQUERY_RESPONSE_TRAILER
            self.alert(event_name=INTERACTION_ALERT_NAME,
                       request=command,
                       orig_ip=address[0],
                       orig_port=address[1])
        else:
            response = ERROR

        if response == ERROR:
            self.debug("Error handling command")
            self.alert(event_name=INTERACTION_ALERT_NAME,
                       request=command,
                       orig_ip=address[0],
                       orig_port=address[1])
            response = ""

        return response


class XeroxPJLServer(object):
    """Xerox PJL Server."""

    def __init__(self, alert_callback, logger):
        self.info = logger.info
        self.debug = logger.debug

        alerting_client_handler = PJLCommandHandler
        alerting_client_handler.debug = logger.debug
        alerting_client_handler.info = logger.info
        alerting_client_handler.alert_callback = alert_callback
        self.pjl = ThreadingPJLServer((LOCALHOST_ADDRESS, PJL_PORT), alerting_client_handler)
        self.pjl.daemon_threads = True
        self.thread = threading.Thread(target=self.pjl.serve_forever)

    def start(self):
        """Start server."""
        self.info(STARTUP_MSG.format(name=SERVER_NAME, port=PJL_PORT))
        self.thread.daemon = True
        try:
            self.thread.start()
        except Exception as err:
            self.debug(ERROR_MSG.format(error=err))
            return False

        return True

    def stop(self):
        """Stop server."""
        self.info(SHUTDOWN_MSG.format(name=SERVER_NAME))
        if self.pjl:
            self.pjl.shutdown()
            self.pjl = None

    def __str__(self):
        return SERVER_NAME
