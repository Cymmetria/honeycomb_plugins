# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import re
import posixpath

import BaseHTTPServer
import SimpleHTTPServer
import urllib
import urlparse

from base_service import ServerCustomService

AMT_PORT = 16992
AMT_AUTH_ATTEMPT_ALERT_TYPE = "intel_amt_auth"
AMT_AUTH_BYPASS_ALERT_TYPE = "intel_amt_bypass"

ALERT_TYPE = "event_type"
DESCRIPTION = "event_description"
ORIGINATING_IP = "originating_ip"
ORIGINATING_PORT = "originating_port"
ADDITIONAL_FIELDS = "additional_fields"
USERNAME = "username"


class AMTServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    server_version = "Intel(R) Active Management Technology 2.6.3"

    def emit(self, alert_dict):
        raise NotImplementedError

    def version_string(self):
        return self.server_version

    def translate_path(self, path):
        """
        Copy of translate_path but instead of start from current directory, change to the dir of the file
        """

        # Abandon query parameters
        path = path.split("?", 1)[0]
        path = path.split("#", 1)[0]
        # Don't forget explicit trailing slash when normalizing. Issue 17324 of
        # SimpleHTTPServer - https://bugs.python.org/issue17324
        trailing_slash = path.rstrip().endswith("/")
        path = posixpath.normpath(urllib.unquote(path))
        words = path.split("/")
        words = filter(None, words)
        path = os.path.dirname(__file__)
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir):
                continue
            path = os.path.join(path, word)
        if trailing_slash:
            path += "/"
        return path

    def do_GET(self):
        parsed_path = urlparse.urlparse(self.path)
        path = parsed_path.path
        if path == "" or path == "/":
            self.send_response(303)
            self.send_header("Location", "/logon.htm")
            self.end_headers()
            return
        if path in ["/index.htm", "/hw-sys.htm"]:
            authorization = self.headers.get("Authorization")
            if authorization is None:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Digest realm="Intel(R) AMT (ID:FE2DAD21-AA72-E211-9722-9134FDA321A2)", nonce="5911b8f9de20f6f1e7c71309a8af03c2", qop="auth"')
                self.end_headers()
                return

            username = None
            usernames = re.findall(r'username="(.*?)"', authorization)
            if usernames:
                username = usernames[0]

            if 'response=""' in authorization:
                self.emit(
                    {
                        ALERT_TYPE: AMT_AUTH_BYPASS_ALERT_TYPE,
                        DESCRIPTION: "Digest Authentication Bypass (CVE-2017-5689)",
                        ORIGINATING_IP: self.client_address[0],
                        ORIGINATING_PORT: self.client_address[1],
                        ADDITIONAL_FIELDS: str(self.headers),
                        USERNAME: username
                    }
                )
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Digest realm="Intel(R) AMT (ID:FE2DAD21-AA72-E211-9722-9134FDA321A2)", nonce="5911b8f9de20f6f1e7c71309a8af03c2", qop="auth"')
                self.end_headers()
                self.emit(
                    {
                        ALERT_TYPE: AMT_AUTH_ATTEMPT_ALERT_TYPE,
                        ORIGINATING_IP: self.client_address[0],
                        ORIGINATING_PORT: self.client_address[1],
                        ADDITIONAL_FIELDS: str(self.headers),
                        USERNAME: username
                    }
                )
                return

        return SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)


class AMTService(ServerCustomService):
    def __init__(self, *args, **kwargs):
        super(AMTService, self).__init__(*args, **kwargs)
        self.server = None

    def on_server_shutdown(self):
        if not self.server:
            return
        self.server.shutdown()

    def on_server_start(self):
        handler = AMTServerHandler
        handler.emit = self.add_alert_to_queue
        self.server = BaseHTTPServer.HTTPServer(("0.0.0.0", AMT_PORT), handler)
        self.signal_ready()
        self.server.serve_forever()

    def __str__(self):
        return "AMT"

service_class = AMTService
