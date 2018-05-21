# -*- coding: utf-8 -*-
"""Micros honeycomb service module."""
from __future__ import unicode_literals

from binascii import unhexlify

import requests
from six.moves.socketserver import ThreadingMixIn
from six.moves.BaseHTTPServer import HTTPServer

import micros_server
from base_service import ServerCustomService

MICROS_PORT = 8080
EVENT_TYPE_FIELD_NAME = "event_type"
MICROS_ALERT_TYPE_NAME = "oracle_micros_dir_traversal"
ORIGINATING_IP_FIELD_NAME = "originating_ip"
ORIGINATING_PORT_FIELD_NAME = "originating_port"
FILE_ACCESSED_FIELD_NAME = "file_accessed"


class NonBlockingHTTPServer(ThreadingMixIn, HTTPServer):
    """Threading HTTPServer stub class."""


class OracleMicrosService(ServerCustomService):
    """Oracle Micros Honeycomb Service."""

    def __init__(self, *args, **kwargs):
        super(OracleMicrosService, self).__init__(*args, **kwargs)
        self.httpd = None

    def alert(self, request, filepath):
        """Send alert."""
        params = {
            EVENT_TYPE_FIELD_NAME: MICROS_ALERT_TYPE_NAME,
            ORIGINATING_IP_FIELD_NAME: request.client_address[0],
            ORIGINATING_PORT_FIELD_NAME: request.client_address[1],
            FILE_ACCESSED_FIELD_NAME: filepath,
        }
        self.add_alert_to_queue(params)

    def on_server_start(self):
        """Initialize service."""
        requestHandler = micros_server.MicrosHandler
        requestHandler.alert_function = self.alert
        requestHandler.listening_port = MICROS_PORT
        requestHandler.logger = self.logger

        self.httpd = NonBlockingHTTPServer(("0.0.0.0", MICROS_PORT), requestHandler)

        self.signal_ready()
        self.logger.info("Oracle MICROS PoS service started on port: %d", MICROS_PORT)

        self.httpd.serve_forever()

    def on_server_shutdown(self):
        """Shut down gracefully."""
        if self.httpd:
            self.logger.info("Oracle MICROS PoS service stopped")
            self.httpd.shutdown()

    def test(self):
        """Trigger service alerts and return a list of triggered event types."""
        exploit = unhexlify("0c2000000010002900000138555651507039787a66697056536e4c75687474703a2f2f736368656d61732e786d"
                            "6c736f61702e6f72672f736f61702f656e76656c6f70652f0000003c3f786d6c2076657273696f6e3d22312e30"
                            "2220656e636f64696e673d227574662d38223f3e3c736f61703a456e76656c6f706520786d6c6e733a736f6170"
                            "3d22687474703a2f2f736368656d61732e786d6c736f61702e6f72672f736f61702f656e76656c6f70652f2220"
                            "786d6c6e733a7873693d22687474703a2f2f7777772e77332e6f72672f323030312f584d4c536368656d612d69"
                            "6e7374616e63652220786d6c6e733a7873643d22687474703a2f2f7777772e77332e6f72672f323030312f584d"
                            "4c536368656d61223e3c736f61703a426f64793e3c50726f6365737344696d655265717565737420786d6c6e73"
                            "3d22687474703a2f2f6d6963726f732d686f7374696e672e636f6d2f45476174657761792f22202f3e3c2f736f"
                            "61703a426f64793e3c2f736f61703a456e76656c6f70653e0a1000000010001800000084555651507039787a66"
                            "697056536e4c756170706c69636174696f6e2f6f637465742d73747265616d01e11e02000000360000003c0053"
                            "0049002d00530065006300750072006900740079002000560065007200730069006f006e003d00220032002200"
                            "20002f003e0058520000000000000000000001c11c0100000001d11db8580000b1360000010000000000000000"
                            "0000001e0000000800000000000000000000001dd1021cc1021ee102")
        headers = {
            "Expect": "100-continue",
            "SOAPAction": '"http://micros-hosting.com/EGateway/ProcessDimeRequest"',
            "Content-Type": "application/dime",
        }
        requests.post("http://localhost:{}/EGateway/EGateway.asmx".format(MICROS_PORT), data=exploit, headers=headers)
        return [MICROS_ALERT_TYPE_NAME]

    def __str__(self):
        return "Oracle MICROS Point-of-Sale"


service_class = OracleMicrosService
