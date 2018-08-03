# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import subprocess
import signal
import json
import logging

from base_service import ServerCustomService

import ldap_server
from ldap_defaults import DEFAULT_DIT_FILENAME, CUSTOM_DIT_FILENAME


logger = logging.getLogger(__name__)

class LdapService(ServerCustomService):
    def __init__(self, *args, **kwargs):
        ServerCustomService.__init__(self, *args, **kwargs)
        self.server = None

    def send_alert(self, eventname, originating_ip, originating_port, eventdesc, **kwargs):
        params = {
                defs.AlertFields.EVENT_TYPE.name : eventname,
                defs.AlertFields.ORIGINATING_IP.name : originating_ip,
                defs.AlertFields.ORIGINATING_PORT.name : originating_port,
                defs.AlertFields.EVENT_DESC.name : eventdesc
                  }
        self.add_alert_to_queue(params)

    def log(self, msg):
        logger.debug(msg)
                    
    def on_server_start(self):
        dit = self.service_args.get("dit", None)
        username = str(self.service_args.get("username"))
        password = str(self.service_args.get("password"))

        if dit != None:
            with open(CUSTOM_DIT_FILENAME, "wb") as fd:
                fd.write(dit)
            dit = CUSTOM_DIT_FILENAME
        else:
            dit = DEFAULT_DIT_FILENAME

        self.signal_ready()
        self.server = ldap_server.LDAPFunctionalServer(send_alert, dit, username, password)
        self.server.serveForever()

    def on_server_shutdown(self):
        self.server.stop()

    def __str__(self):
        return "LDAP"

service_class = LdapService
