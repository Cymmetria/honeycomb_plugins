# -*- coding: utf-8 -*-
"""Intel AMT Honeycomb Service."""
from __future__ import unicode_literals

from base_service import ServerCustomService

from cve_2018_10933_server import SSHServer
from consts import CVE_ALERT_TYPE, EVENT_TYPE_FIELD_NAME, ORIGINATING_IP_FIELD_NAME, ORIGINATING_PORT_FIELD_NAME,\
    SOCK_IP_POSITION, SOCK_PORT_POSITION, CVE_PORT_FIELD



class CVEService(ServerCustomService):
    """Intel AMT Honeycomb Service."""

    def __init__(self, *args, **kwargs):
        super(CVEService, self).__init__(*args, **kwargs)
        self.server = None
        self.transport = None
        self.chan = None

    def alert(self, sock, event_type=CVE_ALERT_TYPE, *args, **kwargs):
        """Send alert."""
        params = {
            EVENT_TYPE_FIELD_NAME: event_type,
            ORIGINATING_IP_FIELD_NAME: sock.getpeername()[SOCK_IP_POSITION],
            ORIGINATING_PORT_FIELD_NAME: sock.getpeername()[SOCK_PORT_POSITION]
        }
        if kwargs:
            params.update(kwargs)
        self.add_alert_to_queue(params)

    def on_server_shutdown(self):
        """Shut down gracefully."""
        self.server.shutdown()

    def on_server_start(self):
        """Initialize service."""
        port = int(self.service_args.get(CVE_PORT_FIELD))
        self.server = SSHServer()
        self.server.alert = self.alert
        self.server.run(port)

    def __str__(self):
        return "CVE 2018 10933"


service_class = CVEService
