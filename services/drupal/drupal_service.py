# -*- coding: utf-8 -*-
"""Drupal CMS honeypot service, for catching CVE-2018-7600 (Drupalgeddon 2)."""
from __future__ import unicode_literals

from base_service import ServerCustomService

from drupal_server import DrupalServer, ALERTS, WEB_PORT

EVENT_TYPE_FIELD_NAME = "event_type"
ORIGINATING_IP_FIELD_NAME = "originating_ip"
ORIGINATING_PORT_FIELD_NAME = "originating_port"
REQUEST_FIELD_NAME = "request"
EXPLOIT_USING_POST = "user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
EXPLOIT_USING_GET = "user/password?name[%23post_render][]=passthru&name[%23markup]=id&name[%23type]=markup"
EXPLOIT_FORMAT = "{target}{exploit}"


class DrupalService(ServerCustomService):
    """Plugin class for Honeycomb/Mazerunner that runs a Drupal CMS service."""

    def __init__(self, *args, **kwargs):
        super(DrupalService, self).__init__(*args, **kwargs)
        self.honeypot = None

    def alert(self, event_name, orig_ip, orig_port, request):
        """Report an alert to the framework."""
        params = {
            EVENT_TYPE_FIELD_NAME: event_name,
            ORIGINATING_IP_FIELD_NAME: orig_ip,
            ORIGINATING_PORT_FIELD_NAME: orig_port,
            REQUEST_FIELD_NAME: request
        }

        self.add_alert_to_queue(params)

    def on_server_start(self):
        """Set up a drupal honeypot server."""
        self.logger.info("{name!s} received start".format(name=self))
        self.honeypot = DrupalServer(self.logger, self.alert)
        self.signal_ready()
        if not self.honeypot.start():
            self.logger.debug("Failed to start simple HTTP Drupal server")

    def on_server_shutdown(self):
        """Stop the honeypot server."""
        self.logger.debug("{name!s} received stop".format(name=self))
        if self.honeypot:
            self.honeypot.stop()

    def test(self):
        """Trigger service alerts and return a list of triggered event types."""
        import requests

        event_types = list()

        self.logger.debug("Executing service test...")

        # Drupal CVE-2018-7600 test - once with POST, once with GET
        target = "http://127.0.0.1:{port}/".format(port=WEB_PORT)
        payload = {"form_id": "user_register_form",
                   "_drupal_ajax": "1",
                   "timezone[a][#lazy_builder][]": "exec",
                   "timezone[a][#lazy_builder][][]": "touch+/tmp/1"}
        requests.post(EXPLOIT_FORMAT.format(target=target, exploit=EXPLOIT_USING_POST), data=payload)
        event_types += ALERTS

        # Now it's GET's turn..
        requests.get(EXPLOIT_FORMAT.format(target=target, exploit=EXPLOIT_USING_GET))
        event_types += ALERTS

        return event_types

    def __str__(self):
        return "Drupal Honeypot"


service_class = DrupalService
