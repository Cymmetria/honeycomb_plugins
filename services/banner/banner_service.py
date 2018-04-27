# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

import banner_server

from utils import defs
from base_service import ServerCustomService

logger = logging.getLogger(__name__)

class BannerService(ServerCustomService):
    def __init__(self, *args, **kwargs):
        super(BannerService, self).__init__(*args, **kwargs)
        self.server = None

    def _send_alert(self, data, originating_ip, originating_port, dest_port):
        params = {
            defs.AlertFields.EVENT_TYPE.name: 'banner_port_access',
            defs.AlertFields.ORIGINATING_IP.name: originating_ip,
            defs.AlertFields.ORIGINATING_PORT.name: originating_port,
            defs.AlertFields.DEST_PORT.name: dest_port,
            defs.AlertFields.EVENT_DESC.name: data,
        }
        self.add_alert_to_queue(params)

    def on_server_start(self):
        logger.info(str(self.service_args))
        port = int(self.service_args["listening_port"])
        banner = self.service_args["banner"].decode('string_escape')
        self.server = banner_server.MultiSocketServer([port], banner, self._send_alert)
        self.signal_ready()
        self.server.serve_forever()

    def on_server_shutdown(self):
        if self.server:
            self.server.close_all()

    def __str__(self):
        return "Banner"

service_class = BannerService









