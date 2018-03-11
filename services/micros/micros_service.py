# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from SocketServer import ThreadingMixIn

import micros_server
from base_service import ServerCustomService

from six.moves.BaseHTTPServer import HTTPServer


MICROS_PORT = 8080
EVENT_TYPE_FIELD_NAME = 'event_type'
MICROS_ALERT_TYPE_NAME = 'oracle_micros_dir_traversal'
ORIGINATING_IP_FIELD_NAME = 'originating_ip'
ORIGINATING_PORT_FIELD_NAME = 'originating_port'
FILE_ACCESSED_FIELD_NAME = 'file_accessed'


class NonBlockingHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class OracleMicrosService(ServerCustomService):
    def __init__(self, *args, **kwargs):
        super(OracleMicrosService, self).__init__(*args, **kwargs)
        self.httpd = None

    def alert(self, request, filepath):
        params = {
            EVENT_TYPE_FIELD_NAME: MICROS_ALERT_TYPE_NAME,
            ORIGINATING_IP_FIELD_NAME: request.client_address[0],
            ORIGINATING_PORT_FIELD_NAME: request.client_address[1],
            FILE_ACCESSED_FIELD_NAME: filepath,
        }
        self.add_alert_to_queue(params)

    def on_server_start(self):
        requestHandler = micros_server.MicrosHandler
        requestHandler.alert_function = self.alert
        requestHandler.listening_port = MICROS_PORT
        requestHandler.logger = self.logger

        self.httpd = NonBlockingHTTPServer(('0.0.0.0', MICROS_PORT), requestHandler)

        self.signal_ready()
        self.logger.info("Oracle MICROS PoS service started on port: %d", MICROS_PORT)

        self.httpd.serve_forever()

    def on_server_shutdown(self):
        if self.httpd:
            self.logger.info("Oracle MICROS PoS service stopped")
            self.httpd.shutdown()

    def __str__(self):
        return "Oracle MICROS Point-of-Sale"


service_class = OracleMicrosService
