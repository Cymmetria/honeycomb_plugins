# -*- coding: utf-8 -*-
"""HP OfficeJet Honeycomb Service."""
from __future__ import unicode_literals

import socket

from base_service import ServerCustomService
import hp_officejet_server as PJL

EVENT_TYPE_FIELD_NAME = "event_type"
ORIGINATING_IP_FIELD_NAME = "originating_ip"
ORIGINATING_PORT_FIELD_NAME = "originating_port"
REQUEST_FIELD_NAME = "request"
TEST_PJL_DOWNLOAD_COMMAND = """@PJL FSDOWNLOAD FORMAT:BINARY SIZE=1337 """ \
                            """NAME="0:/../../rw/var/etc/profile.d/lol.sh"\r\n"""
TEST_PJL_QUERY_COMMAND = """@PJL FSQUERY NAME="0:/../../rw/var/etc/profile.d/lol.sh"\r\n"""


class PJLService(ServerCustomService):
    """HP OfficeJet Honeycomb service class."""

    def __init__(self, *args, **kwargs):
        super(PJLService, self).__init__(*args, **kwargs)
        self.server = None

    def alert(self, event_name, orig_ip, orig_port, request):
        """Raise an alert."""
        params = {
            EVENT_TYPE_FIELD_NAME: event_name,
            ORIGINATING_IP_FIELD_NAME: orig_ip,
            ORIGINATING_PORT_FIELD_NAME: orig_port,
            REQUEST_FIELD_NAME: request
        }

        self.add_alert_to_queue(params)

    def on_server_start(self):
        """Initialize service."""
        self.server = PJL.PJLServer(self.alert, self.logger)
        self.signal_ready()
        self.server.start()

    def on_server_shutdown(self):
        """Shut down gracefully."""
        self.server.shutdown()

    def __str__(self):
        return PJL.SERVER_NAME

    def test(self):
        """Trigger service alerts and return a list of triggered event types."""
        self.logger.debug("executing service test")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((PJL.LOCALHOST_ADDRESS, PJL.PJL_PORT))
        s.settimeout(5)
        s.send(TEST_PJL_DOWNLOAD_COMMAND.encode())
        s.send(TEST_PJL_QUERY_COMMAND.encode())
        event_types = [PJL.ATTACK_ALERT_NAME, PJL.INTERACTION_ALERT_NAME]

        return event_types


service_class = PJLService
