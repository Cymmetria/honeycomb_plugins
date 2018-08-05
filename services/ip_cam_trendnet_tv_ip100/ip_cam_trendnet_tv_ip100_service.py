# -*- coding: utf-8 -*-
"""Honeycomb IP Cam TRENDnet TV-IP100 Service."""
from __future__ import unicode_literals

import os

from six.moves.BaseHTTPServer import HTTPServer

from six.moves.socketserver import ThreadingMixIn

import requests

from honeycomb.servicemanager.base_service import ServerCustomService

from ip_cam_trendnet_tv_ip100_handler import TrendnetTVIP100CamRequestHandler
from consts import EVENT_TYPE_FIELD_NAME, TRENDNET_ADMIN_ACCESS_EVENT, \
    TRENDNET_ADMIN_POST_ATTEMPT, ORIGINATING_IP_FIELD_NAME, ORIGINATING_PORT_FIELD_NAME, REQUEST_FIELD_NAME, \
    DEFAULT_SERVER_VERSION


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Threading HTTP Server stub class."""


class IPCamTrendnetTvIp100Service(ServerCustomService):
    """IP Cam TRENDnet TV-IP100 Service."""

    httpd = None

    def alert(self, request, event):
        """Raise an alert."""
        params = {
            EVENT_TYPE_FIELD_NAME: event,
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
        requestHandler.image_src_url = self.service_args.get("image_src_url", None)
        requestHandler.image_src_path = self.service_args.get("image_src_path", None)

        if requestHandler.image_src_path and requestHandler.image_src_url:
            raise ValueError("cannot process both image_src_path and image_src_url")

        if not requestHandler.image_src_path and not requestHandler.image_src_url:
            raise ValueError("image_src_path or image_src_url must be provided")

        port = self.service_args.get("port")
        threading = self.service_args.get("threading", False)
        if threading:
            self.httpd = ThreadingHTTPServer(("", port), requestHandler)
        else:
            self.httpd = HTTPServer(("", port), requestHandler)

        self.signal_ready()
        self.logger.info(
            "Starting {}IP Cam TRENDnet TV-IP100 service on port: {}".format("Threading " if threading else "", port))
        self.httpd.serve_forever()

    def on_server_shutdown(self):
        """Shut down gracefully."""
        if self.httpd:
            self.httpd.shutdown()
            self.logger.info("IP Cam TRENDnet TV-IP100 service stopped")
            self.httpd = None

    def test(self):
        """Test service alerts and return a list of triggered event types."""
        event_types = list()
        self.logger.debug("executing service test")
        # One alert for authorization attempt
        requests.get("http://localhost:{}/content.html".format(self.service_args.get("port")),
                     headers={"Authorization": "username=\"test\""})
        event_types.append(TRENDNET_ADMIN_ACCESS_EVENT)
        # And one for POST
        requests.post("http://localhost:{}/content.html".format(self.service_args.get("port")), data={})
        event_types.append(TRENDNET_ADMIN_POST_ATTEMPT)
        return event_types

    def __str__(self):
        return "IP Cam TRENDnet TV-IP100"


service_class = IPCamTrendnetTvIp100Service
