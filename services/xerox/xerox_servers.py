# -*- coding: utf-8 -*-
"""Xerox Honeycomb Server Module."""
from __future__ import unicode_literals

import pjl_server
import web_server

from common_strings import ERROR_MSG


class XeroxHoneypot(object):
    """Xerox Honeycomb Server."""

    def __init__(self, alert_callback, logger):
        self.info = logger.info
        self.debug = logger.debug

        self.web = web_server.XeroxWebServer(alert_callback, logger)
        self.web.logger = logger
        self.pjl = pjl_server.XeroxPJLServer(alert_callback, logger)
        self.pjl.logger = logger

    def start(self):
        """Start server."""
        self.info("Starting {name}".format(name=self))
        try:
            self.web.start()
            self.pjl.start()
            self.pjl.thread.join()
        except Exception as err:
            self.debug(ERROR_MSG.format(error=err))
            self.stop()

    def stop(self):
        """Stop server."""
        self.pjl.stop()
        self.web.stop()

    def __str__(self):
        return "Xerox Honeypot Server"
