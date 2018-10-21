# -*- coding: utf-8 -*-
"""Intel AMT Honeycomb Service."""
from __future__ import unicode_literals

import socket
import sys
import paramiko
from paramiko.ssh_exception import SSHException

from base_service import ServerCustomService

from cve_2018_10933_server import CVETransport, SSHServer

CVE_SSH_PORT = 2200
CVE_ALERT_TYPE = "cve_2018_10933_ssh_bypass"
CVE_PORT_FIELD = "port"

EVENT_TYPE_FIELD_NAME = "event_type"
ORIGINATING_IP_FIELD_NAME = "originating_ip"
ORIGINATING_PORT_FIELD_NAME = "originating_port"
SOCK_IP_POSITION = 0
SOCK_PORT_POSITION = 1

host_key = paramiko.RSAKey(filename="./test_rsa.key")


class CVEService(ServerCustomService):
    """Intel AMT Honeycomb Service."""

    def __init__(self, *args, **kwargs):
        super(CVEService, self).__init__(*args, **kwargs)
        self.transport = None
        self.chan = None

    def alert(self, sock):
        """Send alert."""
        params = {
            EVENT_TYPE_FIELD_NAME: CVE_ALERT_TYPE,
            ORIGINATING_IP_FIELD_NAME: sock.getpeername()[SOCK_IP_POSITION],
            ORIGINATING_PORT_FIELD_NAME: sock.getpeername()[SOCK_PORT_POSITION]
        }
        self.add_alert_to_queue(params)

    def on_server_shutdown(self):
        """Shut down gracefully."""
        if self.transport:
            self.transport.close()
        if self.chan:
            self.chan.close()

    def on_server_start(self):
        """Initialize service."""
        try:
            port = int(self.service_args.get(CVE_PORT_FIELD))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", port))
        except Exception as e:
            self.logger.debug("Bind failed %s", e)
            sys.exit(1)

        try:
            sock.listen(100)
            self.logger.debug("Listening for connection ...")
            client, addr = sock.accept()
        except Exception as e:
            self.logger.debug("Listen/accept failed: %s", e)
            sys.exit(1)

        try:
            self.transport = CVETransport(client, gss_kex=True)
            self.transport.alert = self.alert
            self.transport.set_gss_host(socket.getfqdn(""))
            try:
                self.transport.load_server_moduli()
            except:
                self.logger.debug("Failed to load moduli -- gex will be unsupported.")
                raise
            self.transport.add_server_key(host_key)
            server = SSHServer()
            try:
                self.transport.start_server(server=server)
            except SSHException:
                self.logger.debug("SSH negotiation failed")
                sys.exit(1)

            # wait for auth
            self.chan = self.transport.accept(20)
            if self.chan is None:
                self.logger.debug("No channel")
                sys.exit(1)

            self.chan.close()

        except Exception as e:
            self.logger.debug("Caught exception: %s", e)
            try:
                self.transport.close()
            except:
                pass
            sys.exit(1)

    def __str__(self):
        return "CVE 2018 10933"


service_class = CVEService
