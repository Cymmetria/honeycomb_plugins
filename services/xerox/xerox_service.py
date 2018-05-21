# -*- coding: utf-8 -*-
"""Xerox Honeycomb Service."""
from __future__ import unicode_literals

import os
import socket
import shutil

import requests

from base_service import ServerCustomService

import xerox_servers as xrx
from web_server import WWW_FOLDER_NAME as SPECIFIC_WWW_FOLDER_NAME

DEFAULT_EXTERNAL_IP = "82.122.69.29"
LOCAL_IP_TOKEN = "%LOCALIP%"
EXTERNAL_IP_TOKEN = "%IPADDRESSPLACEHOLDER%"
HOSTNAME_TOKEN = "%HOSTNAMETOKEN%"
IPV6_TOKEN = "%IPV6ADDRESS%"
DEFAULT_IPV6 = "fe80::9e93:4eff:fe2e:7f84%7"
PRISTINE_WWW_FOLDER_NAME = "www2"
EVENT_TYPE_FIELD_NAME = "event_type"
ORIGINATING_IP_FIELD_NAME = "originating_ip"
ORIGINATING_PORT_FIELD_NAME = "originating_port"
REQUEST_FIELD_NAME = "request"
TEST_PJL_DOWNLOAD_COMMAND = """@PJL FSDOWNLOAD FORMAT:BINARY SIZE=1337 """ \
                            """NAME="0:/../../rw/var/etc/profile.d/lol.sh"\r\n"""
TEST_PJL_QUERY_COMMAND = """@PJL FSQUERY NAME="0:/../../rw/var/etc/profile.d/lol.sh"\r\n"""


class XeroxService(ServerCustomService):
    """Xerox Honeycomb Service."""

    def __init__(self, *args, **kwargs):
        super(XeroxService, self).__init__(*args, **kwargs)
        self.honeypot = None
        self.external_ip = None

    def alert(self, event_name, orig_ip, orig_port, request):
        """Raise an alert."""
        params = {
            EVENT_TYPE_FIELD_NAME: event_name,
            ORIGINATING_IP_FIELD_NAME: orig_ip,
            ORIGINATING_PORT_FIELD_NAME: orig_port,
            REQUEST_FIELD_NAME: request
        }

        self.add_alert_to_queue(params)

    def get_ipv6(self, host):
        """Get local IPv6 address."""
        all_addresses = socket.getaddrinfo(host, xrx.web_server.WEB_PORT)
        ipv6 = [x for x in all_addresses if x[0] == socket.AF_INET6]
        try:
            return ipv6[0][4][0]
        except Exception:
            return None

    def prepare_web_folder(self):
        """Create mock web content folder."""
        old_directory = os.getcwd()
        os.chdir(os.path.join(os.path.dirname(__file__)))

        try:
            shutil.rmtree(SPECIFIC_WWW_FOLDER_NAME)
        except Exception:
            pass  # This should only happen if we're a fresh instance. It's fine.

        shutil.copytree(PRISTINE_WWW_FOLDER_NAME, SPECIFIC_WWW_FOLDER_NAME)
        self.detokenize(SPECIFIC_WWW_FOLDER_NAME)
        os.chdir(old_directory)

    def detokenize(self, folder):
        """Replace tokens with dynamic content."""
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        local_ipv6 = self.get_ipv6(hostname) or DEFAULT_IPV6
        local_ipv6 = local_ipv6[:local_ipv6.rfind("%")]  # It adds a scope to the end which we don't like

        for directory_name, subdirlist, files in os.walk(folder):
            for filename in files:
                with open(directory_name + "/" + filename, "r+b") as fd:
                    try:
                        buf = fd.read()
                        buf = buf.replace(LOCAL_IP_TOKEN, local_ip)
                        buf = buf.replace(EXTERNAL_IP_TOKEN, self.external_ip)
                        buf = buf.replace(HOSTNAME_TOKEN, hostname)
                        buf = buf.replace(IPV6_TOKEN, local_ipv6)

                        fd.seek(0)
                        fd.write(buf)
                        fd.truncate()
                    except Exception:
                        pass  # This should only happen on GIFs and such. It's fine.

    def on_server_start(self):
        """Initialize service."""
        self.logger.info("{name} received start".format(name=str(self)))
        self.honeypot = xrx.XeroxHoneypot(self.alert, self.logger)
        self.external_ip = self.service_args.get("ip", DEFAULT_EXTERNAL_IP)
        self.prepare_web_folder()
        self.signal_ready()
        if not self.honeypot.start():
            self.logger.debug("Failed to start Xerox honeypot")

    def on_server_shutdown(self):
        """Shut down gracefully."""
        self.logger.debug("{name} received stop".format(name=str(self)))
        if self.honeypot:
            self.honeypot.stop()

    def test(self):
        """Trigger service alerts and return a list of triggered event types."""
        event_types = list()

        self.logger.debug("executing service test")

        # PJL alert tests
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((xrx.pjl_server.LOCALHOST_ADDRESS, xrx.pjl_server.PJL_PORT))
        s.settimeout(5)
        s.send(TEST_PJL_QUERY_COMMAND.encode())     # Interaction
        s.send(TEST_PJL_DOWNLOAD_COMMAND.encode())  # Path Traversal
        s.close()
        event_types += xrx.pjl_server.ALERTS

        # Web alert tests
        requests.get("http://localhost:{}/".format(xrx.web_server.WEB_PORT))
        event_types += xrx.web_server.ALERTS

        return event_types

    def __str__(self):
        return "Xerox Honeypot Service"


service_class = XeroxService
