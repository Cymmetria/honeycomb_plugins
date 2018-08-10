# -*- coding: utf-8 -*-
"""Honeycomb IP Cam TRENDnet TV-IP100 Handler."""
from __future__ import unicode_literals

import os

from six.moves.urllib import parse as urlparse
from six.moves.SimpleHTTPServer import SimpleHTTPRequestHandler

import requests

from consts import TRENDNET_ADMIN_ACCESS_EVENT, TRENDNET_ADMIN_POST_ATTEMPT, CAMERA_IMAGE_PATH, DEFAULT_CONTENT_TYPE


class TrendnetTVIP100CamRequestHandler(SimpleHTTPRequestHandler, object):
    """Handler for Http requests to mimic the IP Cam TRENDnet TV-IP100 website."""

    image_src_url = None
    image_src_path = None
    camera_image_path = CAMERA_IMAGE_PATH

    def _get_fake_image_and_content_type(self):
        if self.image_src_url:
            req_data = requests.get(self.image_src_url)
            return req_data.content, req_data.headers["Content-Type"]
        if self.image_src_path:
            with open(self.image_src_path, "rb") as image_file_handle:
                req_data = image_file_handle.read()
                return req_data, DEFAULT_CONTENT_TYPE
        return None

    @property
    def post_redirect_target(self):
        """Where post requests go."""
        return "/Content.html"

    def send_response(self, code, message=None):
        """Override SimpleHTTPRequestHandler to manipulate headers (otherwise no changes)."""
        self.log_request(code)
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ""
        if self.request_version != "HTTP/0.9":
            data = "%s %d %s\r\n" % (self.protocol_version, code, message)
            self.wfile.write(data.encode())
            # print (self.protocol_version, code, message)

        # Add some recognizable headers
        self.send_header("Auther", "Steven Wu")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("MIME-version", "1.0")
        self.send_header("Server", self.version_string())

    def send_head(self):
        """Override SimpleHTTPRequestHandler to manipulate headers (otherwise no changes)."""
        path = self.translate_path(self.path)
        f = None
        if os.path.isdir(path):
            parts = urlparse.urlsplit(self.path)
            if not parts.path.endswith("/"):
                # redirect browser - doing basically what apache does
                self.send_response(301)
                new_parts = (parts[0], parts[1], parts[2] + "/",
                             parts[3], parts[4])
                new_url = urlparse.urlunsplit(new_parts)
                self.send_header("Location", new_url)
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        ctype = self.guess_type(path)
        try:
            # Always read in binary mode. Opening files in text mode may cause
            # newline translations, making the actual size of the content
            # transmitted *less* than the content-length!
            f = open(path, "rb")
        except IOError:
            self.send_error(404, "File not found")
            return None
        try:
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            fs = os.fstat(f.fileno())
            self.send_header("Content-Length", str(fs[6]))
            self.end_headers()
            return f
        except Exception:
            f.close()
            raise

    def do_GET(self):
        """Override SimpleHTTPRequestHandler to serve a fake image and alert on authentication attempts."""
        if self.path.lower().startswith(self.camera_image_path.lower()):
            image_data_content, image_data_headers = self._get_fake_image_and_content_type()
            self.send_response(200)
            self.send_header("Content-Type", image_data_headers)
            self.end_headers()
            self.wfile.write(image_data_content)
        elif self.path.lower().startswith("/content.htm"):
            authorization = self.headers.get("Authorization")
            # Trying to connect to admin causes an alert
            if authorization:
                self.alert(self, TRENDNET_ADMIN_ACCESS_EVENT)
            self.send_response(401)
            self.send_header("WWW-Authenticate", "BASIC realm=\"Administrator\"")
            self.end_headers()
            self.wfile.write("Password Error. ")
        else:
            super(TrendnetTVIP100CamRequestHandler, self).do_GET()

    def do_POST(self):
        """Provide POST behavior to mimic an authentication failure and alert."""
        # Any POST is an alert
        self.alert(self, TRENDNET_ADMIN_POST_ATTEMPT)

        # Redirect to failed login page
        self.send_response(303)
        self.send_header("Location", self.post_redirect_target)
        self.end_headers()

    def version_string(self):
        """Camera Web Server header."""
        return self.server_version

    def log_error(self, msg, *args):
        """Log an error."""
        self.log_message("error", msg, *args)

    def log_request(self, code="-", size="-"):
        """Log a request."""
        self.log_message("debug",
                         "\"{:s}\" {:s} {:s}".format(self.requestline.replace("%", "%%"), str(code), str(size)))

    def log_message(self, level, msg, *args):
        """Send message to logger with standard apache format."""
        getattr(self.logger, level)(
            "{:s} - - [{:s}] {:s}".format(self.client_address[0], self.log_date_time_string(),
                                          msg % args))
