# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import socket
import logging

from six.moves.socketserver import ThreadingTCPServer, StreamRequestHandler

from base_service import ServerCustomService

logger = logging.getLogger(__name__)

BANNER = "banner"
PORT = "port"
BANNER_ALERT_TYPE_NAME = "banner_port_access"


class BannerRequestHandler(StreamRequestHandler):
    """Request handler for banner service."""

    alert = None
    banner = None

    def handle(self):
        """Handle all requests by sending out our banner."""
        self.alert(self.client_address[0], self.client_address[1])
        self.wfile.write(bytes(self.banner))
        self.wfile.flush()


class BannerService(ServerCustomService):
    """Simple service that will print out banner and hang."""

    def __init__(self, *args, **kwargs):
        """Initialize service."""
        super(BannerService, self).__init__(*args, **kwargs)
        self.server = None

    def _send_alert(self, originating_ip, originating_port):
        params = {
            'event_type': BANNER_ALERT_TYPE_NAME,
            'originating_ip': originating_ip,
            'originating_port': originating_port,
        }
        self.add_alert_to_queue(params)

    def on_server_start(self):
        """Start banner service."""
        requestHandler = BannerRequestHandler
        requestHandler.banner = self.service_args.get(BANNER)
        requestHandler.alert = self._send_alert

        port = int(self.service_args.get(PORT))
        self.server = ThreadingTCPServer(('', port), requestHandler)

        self.signal_ready()
        self.logger.info("Starting Banner service on port {}".format(port))
        self.server.serve_forever()

    def on_server_shutdown(self):
        """Stop banner service."""
        if self.server:
            self.server.shutdown()
            self.logger.info("Banner service stopped")
            self.server = None

    def test(self):
        """Test service alerts and return a list of triggered event types."""
        event_types = list()

        self.logger.debug('executing service test')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(('127.0.0.1', int(self.service_args.get(PORT))))
        s.close()
        event_types.append(BANNER_ALERT_TYPE_NAME)

        return event_types

    def __str__(self):
        """Service name."""
        return "Banner"


service_class = BannerService
