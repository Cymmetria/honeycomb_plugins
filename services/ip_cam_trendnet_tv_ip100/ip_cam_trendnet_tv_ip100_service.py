# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os

import requests
from six.moves.BaseHTTPServer import HTTPServer
from six.moves.SimpleHTTPServer import SimpleHTTPRequestHandler
from six.moves.socketserver import ThreadingMixIn

from honeycomb.servicemanager.base_service import ServerCustomService

DEFAULT_PORT = 8080
EVENT_TYPE_FIELD_NAME = "event_type"
TRENDNET_ADMIN_ACCESS_EVENT = "trendnet_tv_ip100_admin_access"
ORIGINATING_IP_FIELD_NAME = "originating_ip"
ORIGINATING_PORT_FIELD_NAME = "originating_port"
REQUEST_FIELD_NAME = "request"
DEFAULT_SERVER_VERSION = "Camera Web Server/1.0"
DEFAULT_IMAGE_PATH = "/image.jpg"

DEFAULT_IMAGE_TO_GET = "http://farm4.static.flickr.com/3559/3437934775_2e062b154c_o.jpg"


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Threading HTTP Server stub class."""


class TrendnetTVIP100CamRequestHandler(SimpleHTTPRequestHandler, object):

    image_src = DEFAULT_IMAGE_TO_GET
    default_image_path = DEFAULT_IMAGE_PATH

    def authenticate(self, data):
        pass

    def _get_fake_image(self):
        return requests.get(self.image_src)

    @staticmethod
    def _get_post_redirect_target():
        return "/Content.html"

    def _send_response_with_content_type(self, code, message=None, content_type="text/html"):
        """Send the response header and log the response code.

        Also send two standard headers with the server software
        version and the current date.

        """
        self.log_request(code)
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            self.wfile.write("%s %d %s\r\n" %
                             (self.protocol_version, code, message))
            # print (self.protocol_version, code, message)

        # Add some recognizable headers
        self.send_header("Auther", "Steven Wu")
        self.send_header("Cache-Control", "no-cache")
        # self.send_header("Content-Type", content_type)
        self.send_header("MIME-version", "1.0")
        self.send_header("Server", self.version_string())

    def send_response(self, code, message=None):
        self._send_response_with_content_type(code, message)
        # super(TrendnetTVIP100CamRequestHandler, self).send_response(code, message)

    def do_GET(self):
        if self.path.lower().startswith(self.default_image_path.lower()):
            image_data = self._get_fake_image()
            self._send_response_with_content_type(200, None)
            # self.send_header("Content-Type", image_data.headers["Content-Type"])
            self.end_headers()
            self.wfile.write(image_data.content)
        elif self.path.lower().startswith("/content.htm"):
            authorization = self.headers.get("Authorization")
            if authorization:
                self.alert(self)
            self._send_response_with_content_type(401, None)
            self.send_header("WWW-Authenticate", "BASIC realm=\"Administrator\"")
            # self.send_header("Content-Type", image_data.headers["Content-Type"])
            self.end_headers()
            self.wfile.write("Password Error. ")
        else:
            super(TrendnetTVIP100CamRequestHandler, self).do_GET()

    def do_POST(self):
        self.alert(self)
        data_len = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(data_len) if data_len else ""
        self.authenticate(data)
        self.send_response(303)
        self.send_header("Location", self._get_post_redirect_target())
        self.end_headers()

    def version_string(self):
        """HTTP Server version header."""
        return self.server_version

    def log_error(self, msg, *args):
        """Log an error."""
        self.log_message("error", msg, *args)

    def log_request(self, code="-", size="-"):
        """Log a request."""
        self.log_message("debug", '"{:s}" {:s} {:s}'.format(self.requestline.replace("%", "%%"), str(code), str(size)))

    def log_message(self, level, msg, *args):
        """Send message to logger with standard apache format."""
        getattr(self.logger, level)(
            "{:s} - - [{:s}] {:s}".format(self.client_address[0], self.log_date_time_string(),
                                          msg % args))


class IPCamTrendnetTvIp100Service(ServerCustomService):
    """Base IP Cam Service."""

    httpd = None

    def __init__(self, *args, **kwargs):
        super(IPCamTrendnetTvIp100Service, self).__init__(*args, **kwargs)

    def alert(self, request):
        """Raise an alert."""
        params = {
            EVENT_TYPE_FIELD_NAME: TRENDNET_ADMIN_ACCESS_EVENT,
            ORIGINATING_IP_FIELD_NAME: request.client_address[0],
            ORIGINATING_PORT_FIELD_NAME: request.client_address[1],
            REQUEST_FIELD_NAME: " ".join([request.command, request.path]),
        }
        self.add_alert_to_queue(params)

    def on_server_start(self):
        """Initialize Service."""
        os.chdir(os.path.join(os.path.dirname(__file__), "www"))
        requestHandler = TrendnetTVIP100CamRequestHandler
        requestHandler.alert = self.alert
        requestHandler.logger = self.logger
        requestHandler.server_version = self.service_args.get("version", DEFAULT_SERVER_VERSION)
        requestHandler.image_src = self.service_args.get("image_src", DEFAULT_SERVER_VERSION)

        port = self.service_args.get("port", DEFAULT_PORT)
        threading = self.service_args.get("threading", False)
        if threading:
            self.httpd = ThreadingHTTPServer(("", port), requestHandler)
        else:
            self.httpd = HTTPServer(("", port), requestHandler)

        self.signal_ready()
        self.logger.info("Starting {}IP Cam base service on port: {}".format("Threading " if threading else "", port))
        self.httpd.serve_forever()

    def on_server_shutdown(self):
        """Shut down gracefully."""
        if self.httpd:
            self.httpd.shutdown()
            self.logger.info("IP Cam base service stopped")
            self.httpd = None

    def test(self):
        """Test service alerts and return a list of triggered event types."""
        event_types = list()
        # TODO: Write real test
        self.logger.debug("executing service test")
        requests.post("http://localhost:{}/Content.html".format(self.service_args.get("port", DEFAULT_PORT)), data={})
        event_types.append(TRENDNET_ADMIN_ACCESS_EVENT)
        return event_types

    def __str__(self):
        return "IP Cam TRENDnet TV-IP100"


service_class = IPCamTrendnetTvIp100Service

