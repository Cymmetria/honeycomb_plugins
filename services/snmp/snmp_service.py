# -*- coding: utf-8 -*-
"""SNMP Honeycomb service - adapting the honeypot to Honeycomb."""
from __future__ import unicode_literals

import os
import re
import posixpath

import requests
from six.moves import BaseHTTPServer
from six.moves import SimpleHTTPServer
from six.moves import urllib

from base_service import ServerCustomService



class SNMPService(ServerCustomService):
    """Intel AMT Honeycomb Service."""

    def __init__(self, *args, **kwargs):
        super(SNMPService, self).__init__(*args, **kwargs)
        self.server = None

    def on_server_shutdown(self):
        """Shut down gracefully."""
        if not self.server:
            return
        # self.server.shutdown()

    def on_server_start(self):
        """Initialize service."""
        # handler = AMTServerHandler
        # handler.emit = self.add_alert_to_queue
        # self.server = BaseHTTPServer.HTTPServer(("0.0.0.0", AMT_PORT), handler)
        # self.signal_ready()
        # self.server.serve_forever()

    def test(self):
        """Trigger service alerts and return a list of triggered event types."""


    def __str__(self):
        return "SNMP"


service_class = SNMPService
