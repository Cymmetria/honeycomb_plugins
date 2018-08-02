# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from six.moves.SimpleHTTPServer import SimpleHTTPRequestHandler

from honeycomb.servicemanager.base_service import ServerCustomService
from services.simple_http.simple_http_service import SimpleHTTPService, HoneyHTTPRequestHandler


DEFAULT_IMAGE_PATH = "/stream/current.cam0.jpeg"


class IPCamBaseHTTPRequestHandler(HoneyHTTPRequestHandler):

    def __init__(self, request, client_address, server):
        self.default_image_path = DEFAULT_IMAGE_PATH
        super(IPCamBaseHTTPRequestHandler, self).__init__(request, client_address, server)

    def setup(self):
        super(IPCamBaseHTTPRequestHandler, self).setup()

    def do_GET(self):

        if self.path == self.default_image_path:
            self.send_response(200)
            self.end_headers()
            self.wfile.write("booooo")
        else:
            super(IPCamBaseHTTPRequestHandler, self).do_GET()

    def send_head(self, *args, **kwargs):
        retrieved_page = super(HoneyHTTPRequestHandler, self).send_head(*args, **kwargs)
        return retrieved_page

    def log_error(self, msg, *args):
        """Log an error."""
        self.log_message("error", msg, *args)

    def log_request(self, code="-", size="-"):
        """Log a request."""
        self.log_message("debug", '"{:s}" {:s} {:s}'.format(self.requestline, str(code), str(size)))

    def log_message(self, level, msg, *args):
        """Send message to logger with standard apache format."""
        getattr(self.logger, level)("{:s} - - [{:s}] {:s}".format(self.client_address[0], self.log_date_time_string(),
                                                                  msg % args))


class IPCamBaseService(SimpleHTTPService):
    def __init__(self, *args, **kwargs):

        super(IPCamBaseService, self).__init__(*args, **kwargs)

    def on_server_start(self):
        """Initialize Service."""
        self._on_server_start_with_handler(IPCamBaseHTTPRequestHandler)

    def __str__(self):
        return "IP Cam Base"


service_class = IPCamBaseService

