# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os

import requests
from six.moves.BaseHTTPServer import HTTPServer
from six.moves.SimpleHTTPServer import SimpleHTTPRequestHandler
from six.moves.socketserver import ThreadingMixIn

from honeycomb.servicemanager.base_service import ServerCustomService

DEFAULT_PORT = 80
DEFAULT_SERVER_VERSION = "Camera Web Server/1.0"
DEFAULT_IMAGE_PATH = "/IMAGE.jpg"
DEFAULT_SRC_IMAGE_PATH = "/tmp/IMAGE.jpg"

DEFAULT_IMAGE_TO_GET = "http://farm4.static.flickr.com/3559/3437934775_2e062b154c_o.jpg"

DEFAULT_CONTENT_TYPE = "image/jpeg"


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Threading HTTP Server stub class."""


class TrendnetTVIP100CamRequestHandler(SimpleHTTPRequestHandler, object):

    image_src_url = DEFAULT_IMAGE_TO_GET
    image_src_path = DEFAULT_SRC_IMAGE_PATH
    default_image_path = DEFAULT_IMAGE_PATH

    def authenticate(self, data):
        """Implement in sub classes to authenticate POST data"""
        pass

    def _get_fake_image_and_content_type(self):
        if self.image_src_url:
            req_data = requests.get(self.image_src_url)
            return req_data.content, req_data.headers["Content-Type"]
        if self.image_src_path:
            with open(self.image_src_path, "rb") as image_file_handle:
                req_data = image_file_handle.read()
                return req_data, DEFAULT_CONTENT_TYPE

    def _get_post_redirect_target(self):
        return self.default_image_path

    def send_response(self, code, message=None):
        super(TrendnetTVIP100CamRequestHandler, self).send_response(code, message)

        # Add some recognizable headers
        self.send_header("Auther", "Steven Wu")

    def do_GET(self):
        if self.path.startswith(self.default_image_path):
            image_data_content, image_data_headers = self._get_fake_image_and_content_type()
            self.send_response(200)
            self.send_header("Content-Type", image_data_headers)
            self.end_headers()
            self.wfile.write(image_data_content)
        else:
            super(TrendnetTVIP100CamRequestHandler, self).do_GET()

    def do_POST(self):
        data_len = int(self.headers.get("Content-length", 0))
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

    # TODO: several possible alerts
    def alert(self, request):
        """Raise an alert."""
        params = {}
        self.add_alert_to_queue(params)

    def on_server_start(self):
        """Initialize Service."""
        os.chdir(os.path.join(os.path.dirname(__file__), "www"))
        requestHandler = TrendnetTVIP100CamRequestHandler
        requestHandler.alert = self.alert
        requestHandler.logger = self.logger
        requestHandler.server_version = self.service_args.get("version", DEFAULT_SERVER_VERSION)
        requestHandler.image_src_url = self.service_args.get("image_src_url", None)
        requestHandler.image_src_path = self.service_args.get("image_src_path", None)

        if requestHandler.image_src_path and requestHandler.image_src_url:
            raise ValueError("cannot process both image_src_path and image_src_url")

        if not requestHandler.image_src_path and not requestHandler.image_src_url:
            raise ValueError("image_src_path or image_src_url must be provided")

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
        # self.logger.debug("executing service test")
        # requests.get("http://localhost:{}/".format(self.service_args.get("port", DEFAULT_PORT)))
        # event_types.append(SIMPLE_HTTP_ALERT_TYPE_NAME)
        return event_types

    def __str__(self):
        return "IP Cam Base Service"


service_class = IPCamTrendnetTvIp100Service

