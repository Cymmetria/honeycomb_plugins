# -*- coding: utf-8 -*-
"""Micros honeycomb server module."""
from __future__ import unicode_literals

import os
import string
import random
import socket
from binascii import hexlify, unhexlify

from six import b
from six.moves.SimpleHTTPServer import SimpleHTTPRequestHandler


class MicrosHandler(SimpleHTTPRequestHandler):
    """Micros Request Handler."""

    logger = None
    alert_function = None
    listening_port = None

    protocol_version = "HTTP/1.1"

    # The following consts are taken from an online exploitation for CVE-2018-2636
    poc_suf_1_1 = "0A100000001000180000"
    poc_suf_1_ses = "66497a3263516c56444c35305045356e"
    poc_suf_1_2 = "6170706C69636174696F6E2F6F637465742D73747265616D01E11E02000000360000003C00530049002D00530065006300" \
                  "750072006900740079002000560065007200730069006F006E003D0022003200220020002F003E00C2AF00000000000000" \
                  "00000001C11C0100000001D11D8EBA0000B13600000100000000000000000000001E000000"
    poc_suf_1_3 = "00000006000000"
    poc_suf_1_4 = "000000240024"
    poc_suf2 = "001dd1021cc1021ee102"

    log_list = "0c200000001000290000013872663850506e79467478667275366577687474703a2f2f736368656d61732e786d6c736f61702" \
               "e6f72672f736f61702f656e76656c6f70652f0000003c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d" \
               "227574662d38223f3e3c736f61703a456e76656c6f706520786d6c6e733a736f61703d22687474703a2f2f736368656d61732" \
               "e786d6c736f61702e6f72672f736f61702f656e76656c6f70652f2220786d6c6e733a7873693d22687474703a2f2f7777772e" \
               "77332e6f72672f323030312f584d4c536368656d612d696e7374616e63652220786d6c6e733a7873643d22687474703a2f2f7" \
               "777772e77332e6f72672f323030312f584d4c536368656d61223e3c736f61703a426f64793e3c50726f6365737344696d6552" \
               "65717565737420786d6c6e733d22687474703a2f2f6d6963726f732d686f7374696e672e636f6d2f45476174657761792f222" \
               "02f3e3c2f736f61703a426f64793e3c2f736f61703a456e76656c6f70653e0a100000001000180000008e72663850506e7946" \
               "74786672753665776170706c69636174696f6e2f6f637465742d73747265616d01e11e02000000360000003c00530049002d0" \
               "0530065006300750072006900740079002000560065007200730069006f006e003d0022003200220020002f003e00a5980000" \
               "000000000000000001c11c0100000001d11d98a20000b13600000100000000000000000000001e00000012000000050000000" \
               "a000000240024006c006f0067001dd1021cc1021ee1020000"

    db_info = "0a10000000100018000000a073713349713550547466326b427353486170706c69636174696f6e2f6f637465742d7374726561" \
              "6d01e11e02000000360000003c00530049002d00530065006300750072006900740079002000560065007200730069006f006e" \
              "003d0022003200220020002f003e00bd8c0000000000000000000001c11c0100000001d11d8896000035530000010000000000" \
              "0000000000001e000000240000000d004462496e666f5265717565737401000000010006006d5370617265080000000000001d" \
              "d1021cc1021ee102"

    micros_info = "0a1000000010001800000084555651507039787a66697056536e4c756170706c69636174696f6e2f6f637465742d737472" \
                  "65616d01e11e02000000360000003c00530049002d00530065006300750072006900740079002000560065007200730069" \
                  "006f006e003d0022003200220020002f003e0058520000000000000000000001c11c0100000001d11db8580000b1360000" \
                  "0100000000000000000000001e0000000800000000000000000000001dd1021cc1021ee102"

    def setup(self):
        """Set up request handler."""
        SimpleHTTPRequestHandler.setup(self)
        self.request.settimeout(1)

    def version_string(self):
        """HTTP Server version header."""
        return "mCommerceMobileWebServer"

    def do_GET(self):
        """Process GET requests.

        Provide static content, replacing dynamic tokens.
        """
        self.close_connection = True
        if (self.path.split("?")[0] == "/EGateway/EGateway.asmx"):
            self.send_response(200)
            self.send_header("Content-Type", "text/xml; charset=utf-8")
            with open(os.path.dirname(os.path.abspath(__file__)) + "/micros/EGateway.asmx", "rb") as fh:
                body = fh.read()
                body = body.replace("%%HOST%%", self.headers.get("Host").split(":")[0])
                body = body.replace("%%PORT%%", str(self.listening_port))
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            with open(os.path.dirname(os.path.abspath(__file__)) + "/micros/404.html", "rb") as fh:
                body = fh.read()
        self.send_header("Content-Length", int(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        """Process POST request.

        Examine the request to ensure it follows expected protocol answer predefined queries.
        """
        self.close_connection = True
        data_len = int(self.headers.get("Content-length", 0))
        if self.headers.get("Content-type") == "application/dime":
            if data_len:
                data = hexlify(self.rfile.read(data_len)).decode() if data_len else ""

                exploit_data = [self.poc_suf_1_1, self.poc_suf_1_ses, self.poc_suf_1_2, self.poc_suf_1_3,
                                self.poc_suf_1_4, self.poc_suf2]
                if all(e in data for e in exploit_data):
                    # request is asking for a specific file
                    filepath = data[data.find(self.poc_suf_1_4):data.find(self.poc_suf2)]
                    filepath = unhexlify(filepath).replace("\x00", "")[2:]
                    self.send_file(filepath)

                elif data == self.log_list:
                    self.send_file("loglist")

                elif self.micros_info in data:
                    self.send_file("micros_info")

                elif self.db_info in data:
                    self.send_file("db_info")

                else:
                    # request is not recognized
                    self.log_request()
            else:
                # request is empty
                self.log_request()
        else:
            # empty POST
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", 0)
            self.end_headers()

    def send_file(self, filepath):
        """Send a file from the mock filesystem."""
        self.alert_function(request=self, filepath=filepath)
        filename = os.path.basename(filepath.replace("\\", "/"))
        r = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
        rnd = hexlify(b(r)).decode()
        head = "0c200000001000290000016d"
        soap = "687474703a2f2f736368656d61732e786d6c736f61702e6f72672f736f61702f656e76656c6f70652f0000003c3f786d6c207" \
               "6657273696f6e3d22312e302220656e636f64696e673d227574662d38223f3e3c736f61703a456e76656c6f706520786d6c6e" \
               "733a736f61703d22687474703a2f2f736368656d61732e786d6c736f61702e6f72672f736f61702f656e76656c6f70652f222" \
               "0786d6c6e733a7873693d22687474703a2f2f7777772e77332e6f72672f323030312f584d4c536368656d612d696e7374616e" \
               "63652220786d6c6e733a7873643d22687474703a2f2f7777772e77332e6f72672f323030312f584d4c536368656d61223e3c7" \
               "36f61703a426f64793e3c50726f6365737344696d6552657175657374526573706f6e736520786d6c6e733a656775726c3d22" \
               "687474703a2f2f74656d707572692e6f72672f223e3c50726f6365737344696d6552657175657374526573756c74202f3e3c2" \
               "f50726f6365737344696d6552657175657374526573706f6e73653e3c2f736f61703a426f64793e3c2f736f61703a456e7665" \
               "6c6f70653e0000000a10000000100018000002"

        si_sec = "6170706c69636174696f6e2f6f637465742d73747265616d01611e02000000360000003c00530049002d005300650063007" \
                 "50072006900740079002000560065007200730069006f006e003d0022003200220020002f003e"

        try:
            with open(os.path.dirname(os.path.abspath(__file__)) + "/micros/" + filename, "rb") as fh:
                data = fh.read()
        except IOError:
            with open(os.path.dirname(os.path.abspath(__file__)) + "/micros/404", "rb") as fh:
                data = fh.read()

        body = unhexlify(head + rnd + soap + rnd + si_sec) + data
        body = body.replace(b"%%HOST%%", b(self.headers.get("Host").split(":")[0]))
        body = body.replace(b"%%PORT%%", b(str(self.listening_port)))

        self.send_response(200)
        self.send_header("Content-Type", "application/dime")
        self.send_header("Content-Length", int(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Log a request."""
        self.logger.debug("%s - - [%s] %s" %
                          (self.client_address[0],
                           self.log_date_time_string(),
                           format % args))

    def handle_one_request(self):
        """Handle a single HTTP request.

        Overriden to not send 501 errors
        """
        self.close_connection = True
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                # An error code has been sent, just exit
                return
            mname = "do_" + self.command
            if not hasattr(self, mname):
                self.log_request()
                self.close_connection = True
                return
            method = getattr(self, mname)
            method()
            self.wfile.flush()  # actually send the response if not already done.
        except socket.timeout as e:
            # a read or a write timed out.  Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
            return
